#!/usr/bin/env python3
"""Adversarial tests for current-file-review-ledger.py."""

from __future__ import annotations

import ast
import errno
import hashlib
import importlib.util
import io
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Callable, cast
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
            "must never be followed\n",
            encoding="utf-8",
        )
        (self.repo / ".gitignore").write_text("build/\n", encoding="utf-8")
        (self.repo / "tracked.txt").write_text("source\n", encoding="utf-8")
        (self.repo / "binary.dat").write_bytes(b"\x00source-binary\xff")
        executable = self.repo / "run.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        (self.repo / "nested").mkdir()
        (self.repo / "nested" / "item.txt").write_text(
            "inside\n",
            encoding="utf-8",
        )
        os.symlink("../secret.txt", self.repo / "external-link")
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-m", "fixture")
        self.source = run_git(self.repo, "rev-parse", "HEAD")

        (self.repo / "tracked.txt").write_text("current\n", encoding="utf-8")
        (self.repo / "binary.dat").unlink()
        (self.repo / "untracked.txt").write_text(
            "untracked\n",
            encoding="utf-8",
        )
        (self.repo / "build").mkdir()
        (self.repo / "build" / "generated.bin").write_bytes(b"\x00generated")
        self.output = self.repo / "audit" / "FILE_REVIEW_LEDGER.csv"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_clean_repository(self, name: str) -> tuple[Path, str, Path]:
        repo = self.root / name
        repo.mkdir()
        run_git(repo, "init", "--initial-branch=main")
        run_git(repo, "config", "user.name", "Ledger Test")
        run_git(repo, "config", "user.email", "ledger@example.invalid")
        (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        run_git(repo, "add", ".")
        run_git(repo, "commit", "-m", "source")
        return (
            repo,
            run_git(repo, "rev-parse", "HEAD"),
            repo / "audit" / "FILE_REVIEW_LEDGER.csv",
        )

    def create_retention_repository(self, name: str) -> tuple[Path, str, Path, str]:
        repo, source, output = self.create_clean_repository(name)
        ledger.generate_ledger(repo, source, output)
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(repo, "commit", "-m", "implementation")
        return repo, source, output, run_git(repo, "rev-parse", "HEAD")

    def generate(self) -> bytes:
        result = ledger.generate_ledger(
            self.repo,
            self.source,
            self.output,
            ignored_policy="inventory",
        )
        data = self.output.read_bytes()
        self.assertEqual(
            result["ledger_sha256"],
            hashlib.sha256(data).hexdigest(),
        )
        return data

    def verify(self, **arguments: object) -> dict[str, str | int]:
        return cast(
            dict[str, str | int],
            ledger.verify_ledger(
                self.repo,
                self.source,
                self.output,
                ignored_policy="inventory",
                **arguments,
            ),
        )

    def rows(self, data: bytes | None = None) -> dict[str, dict[str, str]]:
        parsed = ledger.parse_ledger(
            data if data is not None else self.output.read_bytes()
        )
        return {row["path"]: row for row in parsed}

    def write_rows(self, rows: list[dict[str, str]]) -> None:
        self.output.write_bytes(ledger.render_ledger(rows))

    def temporary_artifacts(self, directory: Path | None = None) -> list[Path]:
        parent = directory or self.output.parent
        if not parent.exists():
            return []
        return sorted(
            path
            for path in parent.iterdir()
            if path.name.startswith(".haldir-ledger-tmp-")
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
            row["reviewer"] = "Sepehr Mahmoudian"
            row["review_status"] = "REVIEWED"
            row["provenance_review_status"] = "CONFIRMED"
            row["provenance_evidence"] = "review/provenance-record"
            row["license_review_status"] = "APPROVED"
            row["license_expression"] = "Apache-2.0 OR MIT"
            row["license_evidence"] = "review/license-record"
            row["disposition"] = "ACCEPTED"
            row["completed_at"] = "2026-07-18T12:00:00Z"

    def test_create_absent_target_is_fsynced_and_exact(self) -> None:
        self.output.parent.mkdir()
        parent_identity = (
            self.output.parent.stat().st_dev,
            self.output.parent.stat().st_ino,
        )
        fsync_kinds: list[str] = []
        original_fsync = os.fsync

        def record_fsync(descriptor: int) -> None:
            current = os.fstat(descriptor)
            identity = (current.st_dev, current.st_ino)
            if stat.S_ISREG(current.st_mode):
                fsync_kinds.append("file")
            elif identity == parent_identity:
                fsync_kinds.append("target-parent")
            else:
                fsync_kinds.append("other-directory")
            original_fsync(descriptor)

        payload = b"exact create-once payload\n"
        with (
            mock.patch.object(ledger.os, "fsync", side_effect=record_fsync),
            ledger.SecureRepository(self.repo) as secure,
        ):
            created = secure.atomic_create(
                "audit/FILE_REVIEW_LEDGER.csv",
                payload,
                deadline=ledger.Deadline.after(10.0),
            )

        self.assertEqual(created.data, payload)
        self.assertEqual(self.output.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o644)
        self.assertGreaterEqual(fsync_kinds.count("file"), 1)
        self.assertGreaterEqual(fsync_kinds.count("target-parent"), 2)
        self.assertEqual(self.temporary_artifacts(), [])

    def test_create_refuses_every_existing_target_type_untouched(self) -> None:
        base = self.repo / "existing"
        base.mkdir()
        regular = base / "regular"
        regular.write_bytes(b"regular-original")
        symlink = base / "symlink"
        os.symlink("../../secret.txt", symlink)
        directory = base / "directory"
        directory.mkdir()
        fifo = base / "fifo"
        os.mkfifo(fifo)
        socket_path = base / "socket"
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        endpoint.bind(str(socket_path))
        endpoint.close()

        targets = (regular, symlink, directory, fifo, socket_path)
        before = {
            target.name: (
                target.lstat().st_dev,
                target.lstat().st_ino,
                target.lstat().st_mode,
                target.lstat().st_size,
            )
            for target in targets
        }
        with ledger.SecureRepository(self.repo) as secure:
            for target in targets:
                with self.subTest(kind=target.name):
                    with self.assertRaisesRegex(
                        ledger.LedgerError,
                        "already exists",
                    ):
                        secure.atomic_create(
                            f"existing/{target.name}",
                            b"new",
                            deadline=ledger.Deadline.after(10.0),
                        )

        after = {
            target.name: (
                target.lstat().st_dev,
                target.lstat().st_ino,
                target.lstat().st_mode,
                target.lstat().st_size,
            )
            for target in targets
        }
        self.assertEqual(after, before)
        self.assertEqual(regular.read_bytes(), b"regular-original")
        self.assertEqual(os.readlink(symlink), "../../secret.txt")
        self.assertTrue(directory.is_dir())
        self.assertEqual(self.temporary_artifacts(base), [])

    def test_concurrent_creators_allow_at_most_one_success_without_clobber(
        self,
    ) -> None:
        self.output.parent.mkdir()
        original_rename = ledger._atomic_rename_noreplace
        boundary = threading.Barrier(2)

        def synchronized_rename(*arguments: object) -> None:
            boundary.wait(timeout=10.0)
            original_rename(*arguments)

        successes: list[bytes] = []
        failures: list[BaseException] = []
        guard = threading.Lock()

        def create(payload: bytes) -> None:
            try:
                with ledger.SecureRepository(self.repo) as secure:
                    secure.atomic_create(
                        "audit/FILE_REVIEW_LEDGER.csv",
                        payload,
                        deadline=ledger.Deadline.after(20.0),
                    )
                with guard:
                    successes.append(payload)
            except BaseException as exc:
                with guard:
                    failures.append(exc)

        with mock.patch.object(
            ledger,
            "_atomic_rename_noreplace",
            side_effect=synchronized_rename,
        ):
            first = threading.Thread(target=create, args=(b"creator-one\n",))
            second = threading.Thread(target=create, args=(b"creator-two\n",))
            first.start()
            second.start()
            first.join(timeout=20.0)
            second.join(timeout=20.0)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ledger.ConcurrentWriterError)
        self.assertEqual(self.output.read_bytes(), successes[0])
        retained = self.temporary_artifacts()
        self.assertEqual(len(retained), 1)
        self.assertIn(retained[0].read_bytes(), {b"creator-one\n", b"creator-two\n"})
        self.assertNotEqual(retained[0].read_bytes(), successes[0])

    def test_atomic_noreplace_unavailable_fails_without_fallback(self) -> None:
        with mock.patch.object(
            ledger,
            "_atomic_rename_noreplace",
            side_effect=ledger._AtomicRenameUnavailableError("primitive unavailable"),
        ):
            with ledger.SecureRepository(self.repo) as secure:
                with self.assertRaisesRegex(
                    ledger.ConcurrentWriterError,
                    "before any rename syscall, proving this attempt did not publish",
                ):
                    secure.atomic_create(
                        "audit/FILE_REVIEW_LEDGER.csv",
                        b"payload",
                        deadline=ledger.Deadline.after(10.0),
                    )
        self.assertFalse(self.output.exists())
        retained = self.temporary_artifacts()
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"payload")

    def test_native_unsupported_rename_errnos_are_proven_nonpublication(
        self,
    ) -> None:
        class FailingRename:
            def __init__(self, error_number: int) -> None:
                self.error_number = error_number
                self.argtypes: object = None
                self.restype: object = None

            def __call__(self, *_arguments: object) -> int:
                ledger.ctypes.set_errno(self.error_number)
                return -1

        class FakeLibrary:
            def __init__(self, error_number: int) -> None:
                native = FailingRename(error_number)
                self.renameatx_np = native
                self.renameat2 = native

        unsupported = (
            ("ENOSYS", errno.ENOSYS),
            ("EINVAL", errno.EINVAL),
            ("ENOTSUP", getattr(errno, "ENOTSUP", errno.EINVAL)),
            ("EOPNOTSUPP", getattr(errno, "EOPNOTSUPP", errno.EINVAL)),
        )
        for index, (name, error_number) in enumerate(unsupported):
            with self.subTest(errno=name):
                target = self.repo / "audit" / f"unsupported-{index}.csv"
                payload = f"reserved-{name}".encode("ascii")
                before = set(self.temporary_artifacts())
                with (
                    mock.patch.object(
                        ledger.ctypes,
                        "CDLL",
                        return_value=FakeLibrary(error_number),
                    ),
                    ledger.SecureRepository(self.repo) as secure,
                ):
                    with self.assertRaisesRegex(
                        ledger.ConcurrentWriterError,
                        "unsupported operation with no namespace effect, proving "
                        "this attempt did not publish",
                    ):
                        secure.atomic_create(
                            f"audit/{target.name}",
                            payload,
                            deadline=ledger.Deadline.after(10.0),
                        )

                self.assertFalse(target.exists())
                retained = set(self.temporary_artifacts()) - before
                self.assertEqual(len(retained), 1)
                self.assertEqual(next(iter(retained)).read_bytes(), payload)

        ambiguous_target = self.repo / "audit" / "ambiguous-native-eio.csv"
        before = set(self.temporary_artifacts())
        with (
            mock.patch.object(
                ledger.ctypes,
                "CDLL",
                return_value=FakeLibrary(errno.EIO),
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.CreationIncompleteError,
                "outcome is unknown",
            ):
                secure.atomic_create(
                    "audit/ambiguous-native-eio.csv",
                    b"ambiguous-retained",
                    deadline=ledger.Deadline.after(10.0),
                )
        self.assertFalse(ambiguous_target.exists())
        retained = set(self.temporary_artifacts()) - before
        self.assertEqual(len(retained), 1)
        self.assertEqual(next(iter(retained)).read_bytes(), b"ambiguous-retained")

    def test_conflict_plus_temporary_close_eio_keeps_typed_retention_report(
        self,
    ) -> None:
        self.output.parent.mkdir()
        temporary_name = f".haldir-ledger-tmp-{os.getpid()}-{'e' * 16}"
        reserved = self.output.parent / temporary_name
        original_close = ledger._OwnedTemporary.close
        close_faults = 0

        def close_then_report_eio(
            temporary: ledger._OwnedTemporary,  # type: ignore[name-defined]
        ) -> None:
            nonlocal close_faults
            original_close(temporary)
            if temporary.state == "RENAME_REJECTED" and close_faults == 0:
                close_faults += 1
                raise OSError(errno.EIO, "injected temporary close failure")

        with (
            mock.patch.object(
                ledger.SecureRepository,
                "_temporary_name",
                return_value=temporary_name,
            ),
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=OSError(errno.EEXIST, "injected target conflict"),
            ),
            mock.patch.object(
                ledger._OwnedTemporary,
                "close",
                new=close_then_report_eio,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.ConcurrentWriterError) as raised:
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"retained after double fault",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertEqual(close_faults, 1)
        self.assertIn(temporary_name, str(raised.exception))
        self.assertIn("canonical candidate", str(raised.exception))
        self.assertFalse(self.output.exists())
        self.assertEqual(reserved.read_bytes(), b"retained after double fault")
        self.assertEqual(stat.S_IMODE(reserved.stat().st_mode), 0o644)

    def test_unknown_rename_plus_close_eio_keeps_reserved_inspection_detail(
        self,
    ) -> None:
        self.output.parent.mkdir()
        temporary_name = f".haldir-ledger-tmp-{os.getpid()}-{'9' * 16}"
        reserved = self.output.parent / temporary_name
        original_close = ledger._OwnedTemporary.close
        close_faults = 0

        def close_then_report_eio(
            temporary: ledger._OwnedTemporary,  # type: ignore[name-defined]
        ) -> None:
            nonlocal close_faults
            original_close(temporary)
            if temporary.state == "RENAME_OUTCOME_UNKNOWN" and close_faults == 0:
                close_faults += 1
                raise OSError(errno.EIO, "injected unknown-outcome close failure")

        with (
            mock.patch.object(
                ledger.SecureRepository,
                "_temporary_name",
                return_value=temporary_name,
            ),
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=OSError(errno.EIO, "injected ambiguous rename failure"),
            ),
            mock.patch.object(
                ledger._OwnedTemporary,
                "close",
                new=close_then_report_eio,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.CreationIncompleteError) as raised:
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"unknown outcome retained bytes",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertEqual(close_faults, 1)
        self.assertIn(temporary_name, str(raised.exception))
        self.assertIn("canonical candidate", str(raised.exception))
        self.assertIn("reserved temporary state", str(raised.exception))
        self.assertFalse(raised.exception.target_creation_confirmed)
        self.assertFalse(self.output.exists())
        self.assertEqual(reserved.read_bytes(), b"unknown outcome retained bytes")

    def test_prepublication_failure_never_unlinks_reserved_name(self) -> None:
        self.output.parent.mkdir()
        with (
            mock.patch.object(
                ledger.os,
                "unlink",
                side_effect=AssertionError("pathname deletion is forbidden"),
            ) as unlink,
            mock.patch.object(
                ledger.os,
                "fchmod",
                side_effect=OSError(errno.EIO, "injected chmod failure"),
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.ConcurrentWriterError,
                "no unlink was attempted",
            ):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"retained partial attempt",
                    deadline=ledger.Deadline.after(10.0),
                )
            unlink.assert_not_called()

        self.assertFalse(self.output.exists())
        retained = self.temporary_artifacts()
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"retained partial attempt")

    def test_rename_success_followed_by_eio_is_publication_unknown(self) -> None:
        self.output.parent.mkdir()
        original_rename = ledger._atomic_rename_noreplace

        def rename_then_report_eio(*arguments: object) -> None:
            original_rename(*arguments)
            raise OSError(errno.EIO, "rename completed before injected report")

        payload = b"published-before-error\n"
        with (
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=rename_then_report_eio,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.CreationIncompleteError,
                "outcome is unknown",
            ) as raised:
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    payload,
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertFalse(raised.exception.target_creation_confirmed)
        self.assertFalse(raised.exception.canonical_creation_verified)
        self.assertEqual(self.output.read_bytes(), payload)
        self.assertEqual(self.temporary_artifacts(), [])

    def test_rename_conflict_errnos_are_proven_not_published(self) -> None:
        self.output.parent.mkdir()
        for index, error_number in enumerate((errno.EEXIST, errno.ENOTEMPTY)):
            with self.subTest(error_number=error_number):
                target = self.output.parent / f"conflict-{index}.csv"
                before = set(self.temporary_artifacts())
                with (
                    mock.patch.object(
                        ledger,
                        "_atomic_rename_noreplace",
                        side_effect=OSError(error_number, "injected conflict"),
                    ),
                    ledger.SecureRepository(self.repo) as secure,
                ):
                    with self.assertRaisesRegex(
                        ledger.ConcurrentWriterError,
                        "proving this attempt did not publish",
                    ):
                        secure.atomic_create(
                            f"audit/{target.name}",
                            f"reserved-{index}".encode(),
                            deadline=ledger.Deadline.after(10.0),
                        )
                self.assertFalse(target.exists())
                retained = set(self.temporary_artifacts()) - before
                self.assertEqual(len(retained), 1)
                self.assertEqual(
                    next(iter(retained)).read_bytes(),
                    f"reserved-{index}".encode(),
                )

    def test_unsupported_prepublication_directory_fsync_fails_closed(self) -> None:
        original_fsync = os.fsync

        def reject_directory_fsync(descriptor: int) -> None:
            current = os.fstat(descriptor)
            if stat.S_ISDIR(current.st_mode):
                raise OSError(errno.EINVAL, "directory fsync unsupported")
            original_fsync(descriptor)

        with (
            mock.patch.object(
                ledger.os,
                "fsync",
                side_effect=reject_directory_fsync,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "required directory fsync is unavailable",
            ):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"never published",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertTrue(self.output.parent.is_dir())
        self.assertFalse(self.output.exists())
        self.assertEqual(self.temporary_artifacts(), [])

    def test_preexisting_parent_components_are_resynced_in_exact_order(self) -> None:
        first = self.repo / "preexisting"
        second = first / "nested"
        second.mkdir(parents=True)
        identities = {
            (self.repo.stat().st_dev, self.repo.stat().st_ino): "root",
            (first.stat().st_dev, first.stat().st_ino): "first",
            (second.stat().st_dev, second.stat().st_ino): "second",
        }
        observed: list[str] = []
        original_fsync = os.fsync

        def record_directory_fsync(descriptor: int) -> None:
            current = os.fstat(descriptor)
            if stat.S_ISDIR(current.st_mode):
                observed.append(identities[(current.st_dev, current.st_ino)])
            original_fsync(descriptor)

        with (
            ledger.SecureRepository(self.repo) as secure,
            mock.patch.object(
                ledger.os,
                "fsync",
                side_effect=record_directory_fsync,
            ),
        ):
            parent, name = secure._open_parent(
                "preexisting/nested/ledger.csv",
                create=True,
            )
            try:
                self.assertEqual(name, "ledger.csv")
            finally:
                parent.close()

        self.assertEqual(observed, ["first", "root", "second", "first"])

    def test_loser_of_parent_mkdir_race_fails_closed(self) -> None:
        component = "mkdir-race"
        parent = self.repo / component
        target = parent / "ledger.csv"
        original_mkdir = os.mkdir
        competitor_installed = False

        def competitor_wins_mkdir(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal competitor_installed
            if os.fsdecode(path) == component and not competitor_installed:
                original_mkdir(path, mode, dir_fd=dir_fd)
                competitor_installed = True
            original_mkdir(path, mode, dir_fd=dir_fd)

        with (
            mock.patch.object(
                ledger.os,
                "mkdir",
                side_effect=competitor_wins_mkdir,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "unsafe or unavailable parent component",
            ):
                secure.atomic_create(
                    f"{component}/ledger.csv",
                    b"must remain unpublished",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertTrue(competitor_installed)
        self.assertTrue(parent.is_dir())
        self.assertFalse(target.exists())
        self.assertEqual(self.temporary_artifacts(parent), [])

    def test_deadline_at_rename_boundary_preserves_prepublication_state(
        self,
    ) -> None:
        original_check = ledger.Deadline.check

        def expire_at_rename(
            deadline: ledger.Deadline,  # type: ignore[name-defined]
            label: str,
        ) -> None:
            if label.startswith("renaming the fsynced temporary"):
                raise ledger.LedgerError("injected rename-boundary deadline")
            original_check(deadline, label)

        with (
            mock.patch.object(
                ledger.Deadline,
                "check",
                new=expire_at_rename,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.ConcurrentWriterError,
                "stopped before the rename attempt",
            ):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"fsynced reserved bytes",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertFalse(self.output.exists())
        retained = self.temporary_artifacts()
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"fsynced reserved bytes")

    def test_temporary_collision_never_deletes_unowned_entry(self) -> None:
        self.output.parent.mkdir()
        name = f".haldir-ledger-tmp-{os.getpid()}-{'a' * 16}"
        collision = self.output.parent / name
        collision.write_bytes(b"unowned-collision")
        before = collision.stat()

        with (
            mock.patch.object(
                ledger.SecureRepository,
                "_temporary_name",
                return_value=name,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.ConcurrentWriterError,
                "collision",
            ):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"payload",
                    deadline=ledger.Deadline.after(10.0),
                )

        after = collision.stat()
        self.assertEqual(collision.read_bytes(), b"unowned-collision")
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertFalse(self.output.exists())

    def test_invalid_generated_temporary_name_is_never_opened(self) -> None:
        escaped = self.repo / "escaped-temporary"
        with (
            mock.patch.object(
                ledger.SecureRepository,
                "_temporary_name",
                return_value="../escaped-temporary",
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "not a reserved basename",
            ):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"must not be opened",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertFalse(escaped.exists())
        self.assertFalse(self.output.exists())
        self.assertEqual(self.temporary_artifacts(), [])

    def test_temporary_identity_fault_reports_preserved_orphan(self) -> None:
        self.output.parent.mkdir()
        original_open = os.open
        original_fstat = os.fstat
        temporary_descriptor = -1

        def capture_temp_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal temporary_descriptor
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            if os.fsdecode(path).startswith(".haldir-ledger-tmp-"):
                temporary_descriptor = descriptor
            return descriptor

        def fail_temp_identity(descriptor: int) -> os.stat_result:
            if descriptor == temporary_descriptor:
                raise OSError(errno.EIO, "injected temporary fstat failure")
            return original_fstat(descriptor)

        with (
            mock.patch.object(
                ledger.os,
                "open",
                side_effect=capture_temp_open,
            ),
            mock.patch.object(
                ledger.os,
                "fstat",
                side_effect=fail_temp_identity,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.ConcurrentWriterError) as raised:
                secure.atomic_create(
                    "audit/identity-fault.csv",
                    b"payload",
                    deadline=ledger.Deadline.after(10.0),
                )

        retained = self.temporary_artifacts()
        self.assertEqual(len(retained), 1)
        self.assertIn(retained[0].name, str(raised.exception))
        self.assertEqual(retained[0].read_bytes(), b"")
        self.assertFalse((self.output.parent / "identity-fault.csv").exists())

    def test_temporary_substitution_or_mutation_is_preserved(self) -> None:
        self.output.parent.mkdir()
        original_rename = ledger._atomic_rename_noreplace

        def substitute(
            source_fd: int,
            source: str,
            destination_fd: int,
            destination: str,
        ) -> None:
            del destination_fd, destination
            os.unlink(source, dir_fd=source_fd)
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_fd,
            )
            try:
                os.write(descriptor, b"substituted-bytes")
            finally:
                os.close(descriptor)
            raise ledger.LedgerError("injected substitution")

        before = set(self.temporary_artifacts())
        with (
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=substitute,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.CreationIncompleteError) as substituted_error:
                secure.atomic_create(
                    "audit/substituted.csv",
                    b"owned",
                    deadline=ledger.Deadline.after(10.0),
                )
        substituted = set(self.temporary_artifacts()) - before
        self.assertEqual(len(substituted), 1)
        substituted_path = next(iter(substituted))
        self.assertEqual(substituted_path.read_bytes(), b"substituted-bytes")
        self.assertIn(substituted_path.name, str(substituted_error.exception))
        self.assertFalse((self.output.parent / "substituted.csv").exists())

        def mutate(
            source_fd: int,
            source: str,
            destination_fd: int,
            destination: str,
        ) -> None:
            del destination_fd, destination
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_APPEND,
                dir_fd=source_fd,
            )
            try:
                os.write(descriptor, b"!")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise ledger.LedgerError("injected mutation")

        before = set(self.temporary_artifacts())
        with (
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=mutate,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.CreationIncompleteError) as mutation_error:
                secure.atomic_create(
                    "audit/mutated.csv",
                    b"owned",
                    deadline=ledger.Deadline.after(10.0),
                )
        mutated = set(self.temporary_artifacts()) - before
        self.assertEqual(len(mutated), 1)
        mutated_path = next(iter(mutated))
        self.assertEqual(mutated_path.read_bytes(), b"owned!")
        self.assertIn(mutated_path.name, str(mutation_error.exception))
        self.assertFalse((self.output.parent / "mutated.csv").exists())
        self.assertIsNotNone(original_rename)

    def test_write_chmod_and_file_fsync_failures_are_bounded(self) -> None:
        self.output.parent.mkdir()
        cases = ("write", "chmod", "file-fsync")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                target = f"audit/fault-{index}.csv"
                before_artifacts = set(self.temporary_artifacts())
                started = time.monotonic()
                if case == "write":
                    patcher = mock.patch.object(
                        ledger.os,
                        "write",
                        side_effect=OSError(errno.EIO, "injected write failure"),
                    )
                elif case == "chmod":
                    patcher = mock.patch.object(
                        ledger.os,
                        "fchmod",
                        side_effect=OSError(errno.EIO, "injected chmod failure"),
                    )
                else:
                    original_fsync = os.fsync
                    failed = False

                    def fail_file_fsync(descriptor: int) -> None:
                        nonlocal failed
                        current = os.fstat(descriptor)
                        if stat.S_ISREG(current.st_mode) and not failed:
                            failed = True
                            raise OSError(errno.EIO, "injected file fsync failure")
                        original_fsync(descriptor)

                    patcher = mock.patch.object(
                        ledger.os,
                        "fsync",
                        side_effect=fail_file_fsync,
                    )
                with patcher:
                    with ledger.SecureRepository(self.repo) as secure:
                        with self.assertRaises(ledger.ConcurrentWriterError):
                            secure.atomic_create(
                                target,
                                b"payload",
                                deadline=ledger.Deadline.after(10.0),
                            )
                self.assertLess(time.monotonic() - started, 5.0)
                self.assertFalse((self.repo / target).exists())
                retained = set(self.temporary_artifacts()) - before_artifacts
                self.assertEqual(len(retained), 1)

    def test_rename_conflict_preserves_existing_target(self) -> None:
        self.output.parent.mkdir()
        original_rename = ledger._atomic_rename_noreplace
        competing = b"competing-target\n"

        def install_competitor_then_rename(
            source_fd: int,
            source: str,
            destination_fd: int,
            destination: str,
        ) -> None:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o644,
                dir_fd=destination_fd,
            )
            try:
                os.write(descriptor, competing)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            original_rename(
                source_fd,
                source,
                destination_fd,
                destination,
            )

        with (
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=install_competitor_then_rename,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.ConcurrentWriterError):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"ours",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertEqual(self.output.read_bytes(), competing)
        retained = self.temporary_artifacts()
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"ours")

    def test_parent_or_repository_swap_fails_closed(self) -> None:
        self.output.parent.mkdir()
        displaced = self.repo / "audit-displaced"
        original_create = ledger.SecureRepository._create_regular_temporary

        def create_then_swap(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            parent_fd: int,
            data: bytes,
            *,
            path: str,
            file_mode: int,
            deadline: ledger.Deadline,  # type: ignore[name-defined]
        ) -> ledger._OwnedTemporary:  # type: ignore[name-defined]
            temporary = original_create(
                secure,
                parent_fd,
                data,
                path=path,
                file_mode=file_mode,
                deadline=deadline,
            )
            self.output.parent.rename(displaced)
            self.output.parent.mkdir()
            return temporary

        with (
            mock.patch.object(
                ledger.SecureRepository,
                "_create_regular_temporary",
                new=create_then_swap,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.ConcurrentWriterError):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"payload",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertFalse(self.output.exists())
        retained = self.temporary_artifacts(displaced)
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"payload")

        root_repo, _source, root_output = self.create_clean_repository("root-binding")
        displaced_root = self.root / "root-binding-displaced"

        def create_then_swap_root(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            parent_fd: int,
            data: bytes,
            *,
            path: str,
            file_mode: int,
            deadline: ledger.Deadline,  # type: ignore[name-defined]
        ) -> ledger._OwnedTemporary:  # type: ignore[name-defined]
            temporary = original_create(
                secure,
                parent_fd,
                data,
                path=path,
                file_mode=file_mode,
                deadline=deadline,
            )
            root_repo.rename(displaced_root)
            root_repo.mkdir()
            return temporary

        with mock.patch.object(
            ledger.SecureRepository,
            "_create_regular_temporary",
            new=create_then_swap_root,
        ):
            with self.assertRaises(ledger.ConcurrentWriterError):
                with ledger.SecureRepository(root_repo) as secure:
                    secure.atomic_create(
                        "audit/FILE_REVIEW_LEDGER.csv",
                        b"root-payload",
                        deadline=ledger.Deadline.after(10.0),
                    )

        self.assertFalse(root_output.exists())
        root_retained = sorted((displaced_root / "audit").glob(".haldir-ledger-tmp-*"))
        self.assertEqual(len(root_retained), 1)
        self.assertEqual(root_retained[0].read_bytes(), b"root-payload")

    def test_parent_swap_before_temporary_creation_fails_closed(self) -> None:
        self.output.parent.mkdir()
        displaced = self.repo / "audit-pre-temporary-displaced"
        original_create = ledger.SecureRepository._create_regular_temporary
        swapped = False

        def swap_then_create(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            parent_fd: int,
            data: bytes,
            *,
            path: str,
            file_mode: int,
            deadline: ledger.Deadline,  # type: ignore[name-defined]
        ) -> ledger._OwnedTemporary:  # type: ignore[name-defined]
            nonlocal swapped
            self.output.parent.rename(displaced)
            self.output.parent.mkdir()
            swapped = True
            return original_create(
                secure,
                parent_fd,
                data,
                path=path,
                file_mode=file_mode,
                deadline=deadline,
            )

        with (
            mock.patch.object(
                ledger.SecureRepository,
                "_create_regular_temporary",
                new=swap_then_create,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.ConcurrentWriterError,
                (
                    "temporary creation failed before publication; .*"
                    "displaced parent directory"
                ),
            ):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"pre-temporary swap payload",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertTrue(swapped)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.temporary_artifacts(), [])
        retained = self.temporary_artifacts(displaced)
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"pre-temporary swap payload")

    def test_parent_fsync_failure_reports_published_incomplete(self) -> None:
        self.output.parent.mkdir()
        parent_stat = self.output.parent.stat()
        parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
        original_fsync = os.fsync
        parent_calls = 0

        def fail_postrename_parent_fsync(descriptor: int) -> None:
            nonlocal parent_calls
            current = os.fstat(descriptor)
            if (
                stat.S_ISDIR(current.st_mode)
                and (current.st_dev, current.st_ino) == parent_identity
            ):
                parent_calls += 1
                if parent_calls == 3:
                    raise OSError(errno.EIO, "injected parent fsync failure")
            original_fsync(descriptor)

        payload = b"parent-fsync-state-is-incomplete\n"
        with (
            mock.patch.object(
                ledger.os,
                "fsync",
                side_effect=fail_postrename_parent_fsync,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.CreationIncompleteError) as published_error:
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    payload,
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertTrue(published_error.exception.target_creation_confirmed)
        self.assertFalse(published_error.exception.canonical_creation_verified)
        self.assertEqual(parent_calls, 3)
        self.assertEqual(self.output.read_bytes(), payload)
        self.assertEqual(self.temporary_artifacts(), [])

    def test_post_rename_hardlink_is_incomplete_and_never_removed(self) -> None:
        self.output.parent.mkdir()
        original_rename = ledger._atomic_rename_noreplace
        alias = self.output.parent / "hardlink-alias.csv"

        def rename_then_link(
            source_fd: int,
            source: str,
            destination_fd: int,
            destination: str,
        ) -> None:
            original_rename(
                source_fd,
                source,
                destination_fd,
                destination,
            )
            os.link(
                destination,
                alias.name,
                src_dir_fd=destination_fd,
                dst_dir_fd=destination_fd,
                follow_symlinks=False,
            )

        with (
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=rename_then_link,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.CreationIncompleteError):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"hardlink-boundary",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertEqual(self.output.read_bytes(), b"hardlink-boundary")
        self.assertEqual(alias.read_bytes(), b"hardlink-boundary")
        self.assertEqual(self.output.stat().st_ino, alias.stat().st_ino)
        self.assertEqual(self.temporary_artifacts(), [])

    def test_post_inventory_failure_never_unlinks_canonical_target(self) -> None:
        original_build = ledger.build_inventory
        calls = 0

        def fail_third_inventory(*arguments: object, **keywords: object) -> object:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeError("injected post-creation inventory failure")
            return original_build(*arguments, **keywords)

        with mock.patch.object(
            ledger,
            "build_inventory",
            side_effect=fail_third_inventory,
        ):
            with self.assertRaises(ledger.CreationIncompleteError):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )

        self.assertEqual(calls, 3)
        self.assertTrue(self.output.is_file())
        retained = self.output.read_bytes()
        self.assertGreater(len(retained), 0)
        self.assertEqual(self.temporary_artifacts(), [])
        self.assertEqual(
            self.verify()["ledger_sha256"],
            hashlib.sha256(retained).hexdigest(),
        )

    def test_generate_binds_created_state_before_delivering_sigint(self) -> None:
        original_create = ledger.SecureRepository.atomic_create

        def create_then_signal(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            path: str,
            data: bytes,
            *,
            deadline: ledger.Deadline | None = None,  # type: ignore[name-defined]
        ) -> ledger.RegularSnapshot:  # type: ignore[name-defined]
            created = original_create(
                secure,
                path,
                data,
                deadline=deadline,
            )
            os.kill(os.getpid(), signal.SIGINT)
            return created

        with mock.patch.object(
            ledger.SecureRepository,
            "atomic_create",
            new=create_then_signal,
        ):
            with self.assertRaises(ledger.CreationIncompleteError):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )

        self.assertTrue(self.output.is_file())
        self.assertEqual(self.temporary_artifacts(), [])
        self.verify()

    def test_verified_creation_finalization_is_definite(self) -> None:
        original_close = ledger._OwnedTemporary.close
        direct_failed = False

        def fail_direct_verified_close(
            temporary: ledger._OwnedTemporary,  # type: ignore[name-defined]
        ) -> None:
            nonlocal direct_failed
            original_close(temporary)
            if temporary.state == "VERIFIED_SUCCESS" and not direct_failed:
                direct_failed = True
                raise OSError(errno.EIO, "injected final descriptor error")

        payload = b"verified before finalization error\n"
        with (
            mock.patch.object(
                ledger._OwnedTemporary,
                "close",
                new=fail_direct_verified_close,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.CreationIncompleteError,
                "was verified as created",
            ) as direct_error:
                secure.atomic_create(
                    "audit/direct-finalization.csv",
                    payload,
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertTrue(direct_error.exception.target_creation_confirmed)
        self.assertTrue(direct_error.exception.canonical_creation_verified)
        direct_target = self.output.parent / "direct-finalization.csv"
        self.assertEqual(direct_target.read_bytes(), payload)
        self.assertEqual(self.temporary_artifacts(), [])

        repo, source, output = self.create_clean_repository("finalization-generate")
        generate_failed = False

        def fail_generate_verified_close(
            temporary: ledger._OwnedTemporary,  # type: ignore[name-defined]
        ) -> None:
            nonlocal generate_failed
            original_close(temporary)
            if temporary.state == "VERIFIED_SUCCESS" and not generate_failed:
                generate_failed = True
                raise OSError(errno.EIO, "injected final descriptor error")

        with mock.patch.object(
            ledger._OwnedTemporary,
            "close",
            new=fail_generate_verified_close,
        ):
            with self.assertRaisesRegex(
                ledger.CreationIncompleteError,
                "canonical ledger was created",
            ) as generate_error:
                ledger.generate_ledger(repo, source, output)

        self.assertTrue(generate_failed)
        self.assertTrue(generate_error.exception.target_creation_confirmed)
        self.assertTrue(generate_error.exception.canonical_creation_verified)
        self.assertTrue(output.is_file())
        self.assertGreater(output.stat().st_size, 0)
        ledger.verify_ledger(repo, source, output)

    def test_generate_preserves_unknown_rename_outcome_wording(self) -> None:
        with mock.patch.object(
            ledger,
            "_atomic_rename_noreplace",
            side_effect=OSError(errno.EIO, "injected unknown rename outcome"),
        ):
            with self.assertRaisesRegex(
                ledger.CreationIncompleteError,
                "creation may have occurred but could not be confirmed",
            ) as raised:
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )

        self.assertFalse(raised.exception.target_creation_confirmed)
        self.assertFalse(raised.exception.canonical_creation_verified)
        self.assertFalse(self.output.exists())
        retained = self.temporary_artifacts()
        self.assertEqual(len(retained), 1)
        self.assertGreater(len(retained[0].read_bytes()), 0)

    def test_generate_preserves_typed_state_for_combined_postrename_faults(
        self,
    ) -> None:
        original_rename = ledger._atomic_rename_noreplace
        original_fsync = ledger.os.fsync
        root_stat = self.repo.stat()
        root_identity = (root_stat.st_dev, root_stat.st_ino)
        child_directory_fsyncs = 0

        def rename_then_signal(*arguments: object) -> None:
            original_rename(*arguments)
            os.kill(os.getpid(), signal.SIGINT)

        def fail_postrename_fsync(descriptor: int) -> None:
            nonlocal child_directory_fsyncs
            current = os.fstat(descriptor)
            if (
                stat.S_ISDIR(current.st_mode)
                and (
                    current.st_dev,
                    current.st_ino,
                )
                != root_identity
            ):
                child_directory_fsyncs += 1
                if child_directory_fsyncs == 3:
                    raise OSError(errno.EIO, "injected post-rename fsync failure")
            original_fsync(descriptor)

        with (
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=rename_then_signal,
            ),
            mock.patch.object(
                ledger.os,
                "fsync",
                side_effect=fail_postrename_fsync,
            ),
        ):
            with self.assertRaises(ledger.CreationIncompleteError):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )

        self.assertEqual(child_directory_fsyncs, 3)
        self.assertTrue(self.output.is_file())
        self.assertEqual(self.temporary_artifacts(), [])

    def test_post_creation_metadata_change_is_detected_without_unlink(self) -> None:
        original_build = ledger.build_inventory
        calls = 0

        def change_metadata_after_third_inventory(
            *arguments: object,
            **keywords: object,
        ) -> object:
            nonlocal calls
            calls += 1
            rows = original_build(*arguments, **keywords)
            if calls == 3:
                current = self.output.stat()
                os.utime(
                    self.output,
                    ns=(current.st_atime_ns, current.st_mtime_ns + 10_000_000),
                )
            return rows

        with mock.patch.object(
            ledger,
            "build_inventory",
            side_effect=change_metadata_after_third_inventory,
        ):
            with self.assertRaises(ledger.CreationIncompleteError):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )

        self.assertEqual(calls, 3)
        self.assertTrue(self.output.is_file())
        self.assertEqual(self.temporary_artifacts(), [])
        self.verify()

    def test_sigint_at_each_ownership_and_rename_boundary_is_reconciled(
        self,
    ) -> None:
        self.output.parent.mkdir()
        original_open = os.open
        original_temporary = ledger._OwnedTemporary
        original_rename = ledger._atomic_rename_noreplace

        def signal_after_temp_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            descriptor = original_open(
                path,
                flags,
                mode,
                dir_fd=dir_fd,
            )
            if os.fsdecode(path).startswith(".haldir-ledger-tmp-"):
                os.kill(os.getpid(), signal.SIGINT)
            return descriptor

        before_artifacts = set(self.temporary_artifacts())
        with mock.patch.object(
            ledger.os,
            "open",
            side_effect=signal_after_temp_open,
        ):
            with ledger.SecureRepository(self.repo) as secure:
                with self.assertRaises(ledger.ConcurrentWriterError):
                    secure.atomic_create(
                        "audit/open-boundary.csv",
                        b"open",
                        deadline=ledger.Deadline.after(10.0),
                    )
        self.assertFalse((self.output.parent / "open-boundary.csv").exists())
        retained = set(self.temporary_artifacts()) - before_artifacts
        self.assertEqual(len(retained), 1)
        self.assertEqual(next(iter(retained)).read_bytes(), b"")

        def signal_after_temp_binding(*arguments: object, **keywords: object) -> object:
            temporary = original_temporary(*arguments, **keywords)
            os.kill(os.getpid(), signal.SIGINT)
            return temporary

        before_artifacts = set(self.temporary_artifacts())
        with mock.patch.object(
            ledger,
            "_OwnedTemporary",
            side_effect=signal_after_temp_binding,
        ):
            with ledger.SecureRepository(self.repo) as secure:
                with self.assertRaises(ledger.ConcurrentWriterError):
                    secure.atomic_create(
                        "audit/binding-boundary.csv",
                        b"binding",
                        deadline=ledger.Deadline.after(10.0),
                    )
        self.assertFalse((self.output.parent / "binding-boundary.csv").exists())
        retained = set(self.temporary_artifacts()) - before_artifacts
        self.assertEqual(len(retained), 1)
        self.assertEqual(next(iter(retained)).read_bytes(), b"")

        before_artifacts = set(self.temporary_artifacts())
        with mock.patch.object(
            ledger,
            "_atomic_rename_noreplace",
            side_effect=KeyboardInterrupt(),
        ):
            with ledger.SecureRepository(self.repo) as secure:
                with self.assertRaises(ledger.CreationIncompleteError):
                    secure.atomic_create(
                        "audit/prerename-boundary.csv",
                        b"before",
                        deadline=ledger.Deadline.after(10.0),
                    )
        self.assertFalse((self.output.parent / "prerename-boundary.csv").exists())
        retained = set(self.temporary_artifacts()) - before_artifacts
        self.assertEqual(len(retained), 1)
        self.assertEqual(next(iter(retained)).read_bytes(), b"before")

        def rename_then_signal(*arguments: object) -> None:
            original_rename(*arguments)
            os.kill(os.getpid(), signal.SIGINT)

        with mock.patch.object(
            ledger,
            "_atomic_rename_noreplace",
            side_effect=rename_then_signal,
        ):
            with ledger.SecureRepository(self.repo) as secure:
                with self.assertRaises(ledger.CreationIncompleteError):
                    secure.atomic_create(
                        "audit/postrename-boundary.csv",
                        b"after",
                        deadline=ledger.Deadline.after(10.0),
                    )
        self.assertEqual(
            (self.output.parent / "postrename-boundary.csv").read_bytes(),
            b"after",
        )
        self.assertEqual(
            set(self.temporary_artifacts()),
            before_artifacts | retained,
        )

    def test_expired_deadline_during_rename_preserves_unknown_outcome(self) -> None:
        self.output.parent.mkdir()
        deadline = ledger.Deadline.after(10.0)

        def expire_then_fail(*_arguments: object) -> None:
            object.__setattr__(deadline, "ends_at", 0.0)
            raise ledger.LedgerError("injected expired operation")

        with (
            mock.patch.object(
                ledger,
                "_atomic_rename_noreplace",
                side_effect=expire_then_fail,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaises(ledger.CreationIncompleteError):
                secure.atomic_create(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    b"payload",
                    deadline=deadline,
                )

        self.assertFalse(self.output.exists())
        retained = self.temporary_artifacts()
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"payload")

    def test_every_descriptor_closes_once_without_reused_fd_close(self) -> None:
        owned_fd, peer_fd = os.pipe()
        owner = ledger._OwnedDescriptor(owned_fd)
        original_close = os.close
        signaled = False

        def close_then_signal(descriptor: int) -> None:
            nonlocal signaled
            original_close(descriptor)
            if descriptor == owned_fd and not signaled:
                signaled = True
                os.kill(os.getpid(), signal.SIGINT)

        try:
            with mock.patch.object(
                ledger.os,
                "close",
                side_effect=close_then_signal,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    owner.close()
            victim_fd = os.open(os.devnull, os.O_RDONLY)
            try:
                self.assertEqual(victim_fd, owned_fd)
                owner.close()
                os.fstat(victim_fd)
            finally:
                original_close(victim_fd)
        finally:
            original_close(peer_fd)

        original_open = ledger.os.open
        original_dup = ledger.os.dup
        original_close = ledger.os.close
        generation = 0
        active: dict[int, int] = {}
        closed: set[tuple[int, int]] = set()
        duplicate_closes: list[int] = []

        def acquire(descriptor: int) -> int:
            nonlocal generation
            self.assertNotIn(descriptor, active)
            generation += 1
            active[descriptor] = generation
            return descriptor

        def tracked_open(*arguments: object, **keywords: object) -> int:
            return acquire(original_open(*arguments, **keywords))

        def tracked_dup(descriptor: int) -> int:
            return acquire(original_dup(descriptor))

        def tracked_close(descriptor: int) -> None:
            if descriptor not in active:
                duplicate_closes.append(descriptor)
                return
            identity = (descriptor, active.pop(descriptor))
            self.assertNotIn(identity, closed)
            closed.add(identity)
            original_close(descriptor)

        with (
            mock.patch.object(
                ledger.os,
                "open",
                side_effect=tracked_open,
            ),
            mock.patch.object(
                ledger.os,
                "dup",
                side_effect=tracked_dup,
            ),
            mock.patch.object(
                ledger.os,
                "close",
                side_effect=tracked_close,
            ),
        ):
            with ledger.SecureRepository(self.repo) as secure:
                secure.atomic_create(
                    "audit/descriptor-success.csv",
                    b"descriptor",
                    deadline=ledger.Deadline.after(10.0),
                )
            with (
                mock.patch.object(
                    ledger.os,
                    "fchmod",
                    side_effect=OSError(errno.EIO, "injected descriptor failure"),
                ),
                ledger.SecureRepository(self.repo) as secure,
            ):
                with self.assertRaises(ledger.ConcurrentWriterError):
                    secure.atomic_create(
                        "audit/descriptor-failure.csv",
                        b"descriptor",
                        deadline=ledger.Deadline.after(10.0),
                    )

        self.assertEqual(duplicate_closes, [])
        self.assertEqual(active, {})
        self.assertEqual(len(closed), generation)

    def test_restart_detects_pre_rename_orphan(self) -> None:
        self.output.parent.mkdir()
        orphan = self.output.parent / f".haldir-ledger-tmp-{os.getpid()}-{'b' * 16}"
        orphan.write_bytes(b"orphan")
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "temporary artifact",
        ):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "RESERVED_TEMPORARY_WITHOUT_TARGET",
        ):
            ledger.generate_ledger(
                self.repo,
                self.source,
                self.output,
                ignored_policy="inventory",
            )
        self.assertEqual(orphan.read_bytes(), b"orphan")
        self.assertFalse(self.output.exists())

    def test_restart_double_scan_rejects_reserved_name_instability(self) -> None:
        self.output.parent.mkdir()
        reserved = self.output.parent / (f".haldir-ledger-tmp-{os.getpid()}-{'f' * 16}")
        original_scandir = ledger.os.scandir
        scans = 0

        def add_reserved_before_second_scan(path: object) -> object:
            nonlocal scans
            scans += 1
            if scans == 2:
                reserved.write_bytes(b"appeared between restart scans")
            return original_scandir(path)

        with (
            mock.patch.object(
                ledger.os,
                "scandir",
                side_effect=add_reserved_before_second_scan,
            ),
            ledger.SecureRepository(self.repo) as secure,
        ):
            with self.assertRaisesRegex(
                ledger.ConcurrentWriterError,
                "restart state changed while inspecting",
            ):
                secure.creation_restart_state(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertEqual(scans, 2)
        self.assertFalse(self.output.exists())
        self.assertEqual(reserved.read_bytes(), b"appeared between restart scans")

    def test_restart_identifies_target_with_reserved_temporary(self) -> None:
        canonical = self.generate()
        reserved = self.output.parent / (f".haldir-ledger-tmp-{os.getpid()}-{'c' * 16}")
        reserved.write_bytes(b"independent reserved state")

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "TARGET_AND_RESERVED_TEMPORARY",
        ):
            ledger.generate_ledger(
                self.repo,
                self.source,
                self.output,
                ignored_policy="inventory",
            )
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "TARGET_AND_RESERVED_TEMPORARY",
        ):
            self.verify()

        self.assertEqual(self.output.read_bytes(), canonical)
        self.assertEqual(reserved.read_bytes(), b"independent reserved state")

    def test_restart_verification_rejects_mode_hardlink_and_symlink(self) -> None:
        mode_repo, mode_source, mode_output = self.create_clean_repository(
            "restart-mode"
        )
        ledger.generate_ledger(mode_repo, mode_source, mode_output)
        mode_bytes = mode_output.read_bytes()
        mode_output.chmod(0o600)
        with self.assertRaisesRegex(ledger.LedgerError, "exactly 0644"):
            ledger.verify_ledger(mode_repo, mode_source, mode_output)
        self.assertEqual(mode_output.read_bytes(), mode_bytes)
        self.assertEqual(stat.S_IMODE(mode_output.stat().st_mode), 0o600)

        link_repo, link_source, link_output = self.create_clean_repository(
            "restart-hardlink"
        )
        ledger.generate_ledger(link_repo, link_source, link_output)
        link_bytes = link_output.read_bytes()
        alias = link_output.with_name("retained-hardlink.csv")
        os.link(link_output, alias)
        with self.assertRaisesRegex(ledger.LedgerError, "hard-link count"):
            ledger.verify_ledger(link_repo, link_source, link_output)
        self.assertEqual(link_output.read_bytes(), link_bytes)
        self.assertEqual(alias.read_bytes(), link_bytes)
        self.assertEqual(link_output.stat().st_ino, alias.stat().st_ino)

        symlink_repo, symlink_source, symlink_output = self.create_clean_repository(
            "restart-symlink"
        )
        ledger.generate_ledger(symlink_repo, symlink_source, symlink_output)
        symlink_bytes = symlink_output.read_bytes()
        retained = symlink_output.with_name("retained-canonical.csv")
        symlink_output.rename(retained)
        os.symlink(retained.name, symlink_output)
        with self.assertRaisesRegex(ledger.LedgerError, "regular file"):
            ledger.verify_ledger(symlink_repo, symlink_source, symlink_output)
        self.assertTrue(symlink_output.is_symlink())
        self.assertEqual(os.readlink(symlink_output), retained.name)
        self.assertEqual(retained.read_bytes(), symlink_bytes)

    def test_restart_verifies_but_never_regenerates_existing_output(self) -> None:
        original = self.generate()
        with mock.patch.object(
            ledger.SecureRepository,
            "atomic_create",
            side_effect=AssertionError("must not be reached"),
        ) as create:
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "already exists",
            ):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )
            create.assert_not_called()

        self.assertEqual(self.output.read_bytes(), original)
        result = self.verify()
        self.assertEqual(
            result["ledger_sha256"],
            hashlib.sha256(original).hexdigest(),
        )

    def test_output_outside_repo_ignored_or_unsafe_parent_is_rejected(self) -> None:
        outside = self.root / "outside-ledger.csv"
        with self.assertRaisesRegex(ledger.LedgerError, "inside the repository"):
            ledger.generate_ledger(
                self.repo,
                self.source,
                outside,
                ignored_policy="inventory",
            )
        self.assertFalse(outside.exists())

        ignored_output = self.repo / "build" / "ignored-ledger.csv"
        with self.assertRaisesRegex(ledger.LedgerError, "is ignored"):
            ledger.generate_ledger(
                self.repo,
                self.source,
                ignored_output,
                ignored_policy="inventory",
            )
        self.assertFalse(ignored_output.exists())

        external = self.root / "external-parent"
        external.mkdir()
        os.symlink(external, self.repo / "unsafe-parent")
        with self.assertRaisesRegex(ledger.LedgerError, "unsafe|parent"):
            ledger.generate_ledger(
                self.repo,
                self.source,
                self.repo / "unsafe-parent" / "ledger.csv",
                ignored_policy="inventory",
            )
        self.assertFalse((external / "ledger.csv").exists())

    def test_cli_and_ast_contain_no_replace_exchange_lock_or_rollback_authority(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        tree = ast.parse(source)
        definitions = {
            node.name
            for node in ast.walk(tree)
            if isinstance(
                node,
                (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            )
        }
        forbidden_definitions = {
            "PublicationLock",
            "PublicationReceipt",
            "PublicationReceiptHolder",
            "RollbackDisposition",
            "RollbackResult",
            "_atomic_exchange",
            "_rollback_publication",
            "acquire_publication_lock",
            "commit_publication",
            "publish",
            "rollback_publication",
        }
        self.assertTrue(forbidden_definitions.isdisjoint(definitions))
        self.assertNotIn("--replace", source)
        self.assertNotIn("_excluded_paths", source)
        self.assertNotIn("import fcntl", source)
        self.assertNotIn("import enum", source)

        forbidden_os_calls: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "os"
                and function.attr in {"link", "rename", "replace", "unlink"}
            ):
                forbidden_os_calls.append(function.attr)
        self.assertEqual(forbidden_os_calls, [])

        parser = ledger._argument_parser()
        with mock.patch("sys.stderr", new_callable=io.StringIO) as refusal:
            with self.assertRaises(SystemExit) as raised:
                parser.parse_args(
                    [
                        "generate",
                        "--repo",
                        str(self.repo),
                        "--source-commit",
                        self.source,
                        "--output",
                        str(self.output),
                        "--replace",
                    ]
                )
        expected_refusal = (
            f"usage: {parser.prog} [-h] {{generate,verify}} ...\n"
            f"{parser.prog}: error: unrecognized arguments: --replace\n"
        )

        def require_exact_refusal(observed: str) -> None:
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(observed, expected_refusal)

        require_exact_refusal(refusal.getvalue())
        with self.assertRaises(AssertionError):
            require_exact_refusal(
                refusal.getvalue().replace(
                    "unrecognized arguments", "accepted arguments", 1
                )
            )

    def test_complete_inventory_is_deterministic_and_initially_unassigned(
        self,
    ) -> None:
        first_rows = ledger.build_inventory(
            self.repo,
            self.source,
            ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
            ignored_policy="inventory",
        )
        second_rows = ledger.build_inventory(
            self.repo,
            self.source,
            ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
            ignored_policy="inventory",
        )
        self.assertEqual(
            ledger.render_ledger(first_rows),
            ledger.render_ledger(second_rows),
        )

        data = self.generate()
        result = self.verify()
        self.assertEqual(
            result["ledger_sha256"],
            hashlib.sha256(data).hexdigest(),
        )
        rows = self.rows(data)
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
        self.assertEqual(
            rows["tracked.txt"]["worktree_state"],
            "CONTENT_OR_TYPE_CHANGED_AGAINST_INDEX",
        )
        self.assertEqual(
            rows["binary.dat"]["worktree_state"],
            "DELETED_FROM_WORKTREE",
        )
        self.assertEqual(rows["run.sh"]["source_git_mode"], "100755")
        self.assertEqual(rows["untracked.txt"]["current_scope"], "UNTRACKED")
        ignored = rows["build/generated.bin"]
        self.assertEqual(ignored["current_scope"], "IGNORED")
        self.assertEqual(ignored["ignore_pattern"], "build/")
        self.assertEqual(rows["external-link"]["current_fs_type"], "SYMLINK")
        self.assertEqual(
            rows["external-link"]["current_sha256"],
            hashlib.sha256(b"../secret.txt").hexdigest(),
        )
        self_row = rows["audit/FILE_REVIEW_LEDGER.csv"]
        self.assertEqual(
            self_row["worktree_state"],
            "SELF_REFERENTIAL_CONTENT_EXCLUDED",
        )
        self.assertEqual(self_row["format"], "SELF_REFERENTIAL_CSV")
        for row in rows.values():
            self.assertEqual(row["reviewer"], "UNASSIGNED")
            self.assertEqual(row["review_status"], "UNREVIEWED")
            self.assertEqual(row["provenance_review_status"], "UNREVIEWED")
            self.assertEqual(row["license_review_status"], "UNREVIEWED")
            self.assertEqual(row["public_surface"], "UNKNOWN")
            self.assertEqual(row["completed_at"], "")

    def test_self_row_survives_stage_commit_and_clean_clone(self) -> None:
        repo, source, output = self.create_clean_repository("lifecycle")
        generated = ledger.generate_ledger(repo, source, output)
        expected = generated["ledger_sha256"]
        self.assertEqual(
            ledger.verify_ledger(repo, source, output)["ledger_sha256"],
            expected,
        )
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        self.assertEqual(
            ledger.verify_ledger(repo, source, output)["ledger_sha256"],
            expected,
        )
        run_git(repo, "commit", "-m", "retain ledger")
        clone = self.root / "lifecycle-clone"
        clone_repository(repo, clone)
        self.assertEqual(
            ledger.verify_ledger(
                clone,
                source,
                clone / "audit" / "FILE_REVIEW_LEDGER.csv",
            )["ledger_sha256"],
            expected,
        )

    def test_current_worktree_change_invalidates_existing_ledger(self) -> None:
        self.generate()
        (self.repo / "tracked.txt").write_text(
            "changed again\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ledger.LedgerError, "immutable field mismatch"):
            self.verify()

    def test_current_verification_rejects_ledger_change_during_inventory(
        self,
    ) -> None:
        self.generate()
        original_build = ledger.build_inventory
        changed = False
        competing = b"changed while verification was running\n"

        def build_then_change(*arguments: object, **keywords: object) -> object:
            nonlocal changed
            result = original_build(*arguments, **keywords)
            if not changed:
                changed = True
                temporary = self.output.with_name("test-only-change.tmp")
                temporary.write_bytes(competing)
                os.replace(temporary, self.output)
            return result

        with mock.patch.object(
            ledger,
            "build_inventory",
            side_effect=build_then_change,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "ledger changed during verification",
            ):
                self.verify()
        self.assertTrue(changed)
        self.assertEqual(self.output.read_bytes(), competing)

    def test_mid_verification_mode_and_hardlink_changes_are_rejected(self) -> None:
        self.generate()
        original_verify_rows = ledger._verify_rows
        mode_changed = False

        def change_mode_after_rows(
            *arguments: object,
            **keywords: object,
        ) -> None:
            nonlocal mode_changed
            original_verify_rows(*arguments, **keywords)
            if not mode_changed:
                self.output.chmod(0o600)
                mode_changed = True

        with mock.patch.object(
            ledger,
            "_verify_rows",
            side_effect=change_mode_after_rows,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "ledger changed during verification",
            ):
                self.verify()
        self.assertTrue(mode_changed)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

        repo, source, output = self.create_clean_repository("mid-verification-hardlink")
        ledger.generate_ledger(repo, source, output)
        hardlink = repo / ".git" / "ledger-verification-hardlink"
        link_created = False

        def add_hardlink_after_rows(
            *arguments: object,
            **keywords: object,
        ) -> None:
            nonlocal link_created
            original_verify_rows(*arguments, **keywords)
            if not link_created:
                os.link(output, hardlink)
                link_created = True

        with mock.patch.object(
            ledger,
            "_verify_rows",
            side_effect=add_hardlink_after_rows,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "ledger changed during verification",
            ):
                ledger.verify_ledger(repo, source, output)
        self.assertTrue(link_created)
        self.assertEqual(output.stat().st_ino, hardlink.stat().st_ino)

    def test_current_verification_rejects_between_pass_worktree_change(self) -> None:
        canonical = self.generate()
        original_build = ledger.build_inventory
        build_calls = 0

        def mutate_after_first_pass(
            *arguments: object,
            **keywords: object,
        ) -> object:
            nonlocal build_calls
            rows = original_build(*arguments, **keywords)
            build_calls += 1
            if build_calls == 1:
                (self.repo / "tracked.txt").write_text(
                    "changed between verification passes\n",
                    encoding="utf-8",
                )
            return rows

        with mock.patch.object(
            ledger,
            "build_inventory",
            side_effect=mutate_after_first_pass,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "between independent current-view verification inventory passes",
            ):
                self.verify()

        self.assertEqual(build_calls, 2)
        self.assertEqual(self.output.read_bytes(), canonical)

    def test_generate_rejects_between_pass_worktree_change(self) -> None:
        original_build = ledger.build_inventory
        build_calls = 0

        def mutate_after_first_pass(
            *arguments: object,
            **keywords: object,
        ) -> object:
            nonlocal build_calls
            rows = original_build(*arguments, **keywords)
            build_calls += 1
            if build_calls == 1:
                (self.repo / "tracked.txt").write_text(
                    "changed between generation passes\n",
                    encoding="utf-8",
                )
            return rows

        with mock.patch.object(
            ledger,
            "build_inventory",
            side_effect=mutate_after_first_pass,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "between independent inventory passes",
            ):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )

        self.assertEqual(build_calls, 2)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.temporary_artifacts(), [])

    def test_verify_double_pass_reuses_exact_deadline_object(self) -> None:
        self.generate()
        original_build = ledger.build_inventory
        observed: list[object] = []
        deadline = ledger.Deadline.after(30.0)

        def capture_deadline(
            *arguments: object,
            **keywords: object,
        ) -> object:
            observed.append(keywords.get("_deadline"))
            return original_build(*arguments, **keywords)

        with mock.patch.object(
            ledger,
            "build_inventory",
            side_effect=capture_deadline,
        ):
            result = ledger.verify_ledger(
                self.repo,
                self.source,
                self.output,
                ignored_policy="inventory",
                _deadline=deadline,
            )

        self.assertEqual(result["verification_view"], "CURRENT_INDEX_AND_WORKTREE")
        self.assertEqual(len(observed), 2)
        self.assertTrue(all(candidate is deadline for candidate in observed))

    def test_final_verification_rejects_late_reserved_temporary(self) -> None:
        canonical = self.generate()
        reserved = self.output.parent / (f".haldir-ledger-tmp-{os.getpid()}-{'d' * 16}")
        original_state = ledger.SecureRepository.creation_restart_state
        state_calls = 0

        def inject_on_final_state_check(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            path: str,
            *,
            deadline: ledger.Deadline,  # type: ignore[name-defined]
        ) -> tuple[os.stat_result | None, tuple[str, ...]]:
            nonlocal state_calls
            state_calls += 1
            if state_calls == 2:
                reserved.write_bytes(b"late reserved state")
            return cast(
                tuple[os.stat_result | None, tuple[str, ...]],
                original_state(secure, path, deadline=deadline),
            )

        with mock.patch.object(
            ledger.SecureRepository,
            "creation_restart_state",
            new=inject_on_final_state_check,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "TARGET_AND_RESERVED_TEMPORARY",
            ):
                self.verify()

        self.assertEqual(state_calls, 2)
        self.assertEqual(self.output.read_bytes(), canonical)
        self.assertEqual(reserved.read_bytes(), b"late reserved state")

    def test_verification_failure_closes_pinned_descriptor(self) -> None:
        self.generate()
        original_pin = ledger.SecureRepository.pin_regular
        captured = -1

        def record_pin(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            path: str,
            *,
            maximum: int,
            deadline: ledger.Deadline,  # type: ignore[name-defined]
        ) -> ledger.PinnedRegularSnapshot:  # type: ignore[name-defined]
            nonlocal captured
            pinned = original_pin(
                secure,
                path,
                maximum=maximum,
                deadline=deadline,
            )
            captured = pinned.descriptor
            return pinned

        with (
            mock.patch.object(
                ledger.SecureRepository,
                "pin_regular",
                new=record_pin,
            ),
            mock.patch.object(
                ledger,
                "build_inventory",
                side_effect=RuntimeError("injected verification failure"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.verify()
        self.assertGreaterEqual(captured, 0)
        with self.assertRaises(OSError) as closed:
            os.fstat(captured)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_secure_view_exit_failure_still_closes_verification_pin(self) -> None:
        canonical = self.generate()
        original_pin = ledger.SecureRepository.pin_regular
        original_exit = ledger.SecureRepository.__exit__
        captured = -1
        injected = False
        retained_pins: list[object] = []

        def record_pin(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            path: str,
            *,
            maximum: int,
            deadline: ledger.Deadline,  # type: ignore[name-defined]
        ) -> ledger.PinnedRegularSnapshot:  # type: ignore[name-defined]
            nonlocal captured
            pinned = original_pin(
                secure,
                path,
                maximum=maximum,
                deadline=deadline,
            )
            captured = pinned.descriptor
            retained_pins.append(pinned)
            return pinned

        def close_view_then_fail(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            exception_type: type[BaseException] | None = None,
            exception: BaseException | None = None,
            traceback: object = None,
        ) -> None:
            nonlocal injected
            original_exit(secure, exception_type, exception, traceback)
            if exception_type is None and captured >= 0 and not injected:
                injected = True
                raise ledger.ConcurrentWriterError(
                    "injected secure-view finalization failure"
                )

        with (
            mock.patch.object(
                ledger.SecureRepository,
                "pin_regular",
                new=record_pin,
            ),
            mock.patch.object(
                ledger.SecureRepository,
                "__exit__",
                new=close_view_then_fail,
            ),
        ):
            with self.assertRaisesRegex(
                ledger.ConcurrentWriterError,
                "secure-view finalization failure",
            ):
                self.verify()

        self.assertTrue(injected)
        self.assertGreaterEqual(captured, 0)
        self.assertEqual(len(retained_pins), 1)
        self.assertEqual(getattr(retained_pins[0], "descriptor"), -1)
        with self.assertRaises(OSError) as closed:
            os.fstat(captured)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        self.assertEqual(self.output.read_bytes(), canonical)

    def test_exact_implementation_snapshot_survives_later_protocol_files(
        self,
    ) -> None:
        repo, source, output = self.create_clean_repository("retention")
        generated = ledger.generate_ledger(repo, source, output)
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(repo, "commit", "-m", "implementation")
        implementation = run_git(repo, "rev-parse", "HEAD")
        (repo / "qualification.json").write_text("{}\n", encoding="utf-8")
        run_git(repo, "add", "qualification.json")
        run_git(repo, "commit", "-m", "qualification")

        with self.assertRaisesRegex(ledger.LedgerError, "row count"):
            ledger.verify_ledger(repo, source, output)
        retained = ledger.verify_ledger(
            repo,
            source,
            output,
            implementation_commit=implementation,
        )
        self.assertEqual(retained["implementation_commit"], implementation)
        self.assertEqual(
            retained["implementation_ledger_sha256"],
            generated["ledger_sha256"],
        )
        self.assertEqual(
            retained["verification_view"],
            "EXACT_IMPLEMENTATION_SNAPSHOT",
        )

    def test_retention_snapshot_uses_child_umask_and_preserves_parent_umask(
        self,
    ) -> None:
        repo, source, output, implementation = self.create_retention_repository(
            "retention-umask"
        )
        previous_umask = os.umask(0o077)
        observed_after_verify: int | None = None
        try:
            retained = ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
            )
        finally:
            observed_after_verify = os.umask(previous_umask)

        self.assertEqual(observed_after_verify, 0o077)
        restored_probe = os.umask(previous_umask)
        self.assertEqual(restored_probe, previous_umask)
        self.assertEqual(retained["implementation_commit"], implementation)
        self.assertEqual(
            retained["verification_view"],
            "EXACT_IMPLEMENTATION_SNAPSHOT",
        )

    def test_retention_rejects_merge_on_first_parent_chain(self) -> None:
        repo, source, output, implementation = self.create_retention_repository(
            "retention-merge"
        )
        run_git(repo, "checkout", "-b", "side", implementation)
        (repo / "side.txt").write_text("side\n", encoding="utf-8")
        run_git(repo, "add", "side.txt")
        run_git(repo, "commit", "-m", "side")
        run_git(repo, "checkout", "main")
        (repo / "main.txt").write_text("main\n", encoding="utf-8")
        run_git(repo, "add", "main.txt")
        run_git(repo, "commit", "-m", "main")
        run_git(repo, "merge", "--no-ff", "side", "-m", "merge")

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "raw first-parent chain must remain merge-free",
        ):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
            )

    def test_retention_requires_implementation_parent_to_equal_source(self) -> None:
        repo, source, output = self.create_clean_repository("retention-parent")
        (repo / "intermediate.txt").write_text("intermediate\n", encoding="utf-8")
        run_git(repo, "add", "intermediate.txt")
        run_git(repo, "commit", "-m", "intermediate")
        ledger.generate_ledger(repo, source, output)
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(repo, "commit", "-m", "implementation")
        implementation = run_git(repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "single-parent child of the exact source commit",
        ):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
            )

    def test_retention_ignores_replace_overlay_that_forges_valid_parent(self) -> None:
        repo, source, output = self.create_clean_repository("retention-replace")
        (repo / "intermediate.txt").write_text("intermediate\n", encoding="utf-8")
        run_git(repo, "add", "intermediate.txt")
        run_git(repo, "commit", "-m", "intermediate")
        ledger.generate_ledger(repo, source, output)
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(repo, "commit", "-m", "implementation")
        implementation = run_git(repo, "rev-parse", "HEAD")
        tree = run_git(repo, "rev-parse", f"{implementation}^{{tree}}")
        replacement = run_git(
            repo,
            "commit-tree",
            tree,
            "-p",
            source,
            "-m",
            "replacement overlay",
        )
        run_git(repo, "replace", implementation, replacement)
        self.assertEqual(run_git(repo, "rev-parse", f"{implementation}^"), source)

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "single-parent child of the exact source commit",
        ):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
            )

    def test_retention_rejects_missing_or_executable_head_ledger(self) -> None:
        missing_repo, missing_source, missing_output, missing_implementation = (
            self.create_retention_repository("retention-missing")
        )
        retained_bytes = missing_output.read_bytes()
        run_git(missing_repo, "rm", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(missing_repo, "commit", "-m", "remove retained ledger")
        missing_output.parent.mkdir()
        missing_output.write_bytes(retained_bytes)
        missing_output.chmod(0o644)
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "requires a 100644 ledger blob",
        ):
            ledger.verify_ledger(
                missing_repo,
                missing_source,
                missing_output,
                implementation_commit=missing_implementation,
            )

        mode_repo, mode_source, mode_output, mode_implementation = (
            self.create_retention_repository("retention-executable")
        )
        mode_output.chmod(0o755)
        run_git(mode_repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(mode_repo, "commit", "-m", "make retained ledger executable")
        self.assertTrue(
            run_git(
                mode_repo,
                "ls-tree",
                "HEAD",
                "audit/FILE_REVIEW_LEDGER.csv",
            ).startswith("100755 blob ")
        )
        mode_output.chmod(0o644)
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "requires a 100644 ledger blob",
        ):
            ledger.verify_ledger(
                mode_repo,
                mode_source,
                mode_output,
                implementation_commit=mode_implementation,
            )

    def test_retained_blob_size_and_object_id_mismatches_are_rejected(self) -> None:
        path = "audit/FILE_REVIEW_LEDGER.csv"
        data = b"retained blob mutation fixture"
        oid = ledger._git_blob_id(data, "sha1")
        deadline = ledger.Deadline.after(10.0)

        size_entry = ledger.SourceEntry("100644", "blob", oid, len(data) + 1)
        with (
            mock.patch.object(
                ledger,
                "_source_entries",
                return_value={path: size_entry},
            ),
            mock.patch.object(ledger, "_run_git", return_value=data),
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "size does not match its tree entry",
            ):
                ledger._commit_regular_blob(
                    self.repo,
                    self.source,
                    path,
                    maximum=1024,
                    deadline=deadline,
                )

        wrong_oid = "0" * 39 + "1"
        oid_entry = ledger.SourceEntry("100644", "blob", wrong_oid, len(data))
        with (
            mock.patch.object(
                ledger,
                "_source_entries",
                return_value={path: oid_entry},
            ),
            mock.patch.object(ledger, "_run_git", return_value=data),
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "does not match its Git object ID",
            ):
                ledger._commit_regular_blob(
                    self.repo,
                    self.source,
                    path,
                    maximum=1024,
                    deadline=deadline,
                )

    def test_retention_rejects_worktree_ledger_substitution(self) -> None:
        repo, source, output, implementation = self.create_retention_repository(
            "retention-worktree-substitution"
        )
        (repo / "qualification.txt").write_text("retained\n", encoding="utf-8")
        run_git(repo, "add", "qualification.txt")
        run_git(repo, "commit", "-m", "qualification")
        rows = ledger.parse_ledger(output.read_bytes())
        rows[0]["assumptions"] = "worktree-only substitution"
        output.write_bytes(ledger.render_ledger(rows))
        output.chmod(0o644)

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "identical to the captured current-HEAD blob",
        ):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
            )

    def test_retention_rejects_tampered_implementation_snapshot(self) -> None:
        repo, source, output = self.create_clean_repository("retention-tampered")
        ledger.generate_ledger(repo, source, output)
        rows = ledger.parse_ledger(output.read_bytes())
        tracked = next(row for row in rows if row["path"] == "tracked.txt")
        tracked["source_sha256"] = "0" * 64
        output.write_bytes(ledger.render_ledger(rows))
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(repo, "commit", "-m", "implementation")
        implementation = run_git(repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(ledger.LedgerError, "immutable field mismatch"):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
            )

    def test_staged_content_identity_is_distinct_from_source_and_worktree(
        self,
    ) -> None:
        (self.repo / "tracked.txt").write_text("staged\n", encoding="utf-8")
        run_git(self.repo, "add", "tracked.txt")
        (self.repo / "tracked.txt").write_text("worktree\n", encoding="utf-8")
        rows = {
            row["path"]: row
            for row in ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )
        }
        target = rows["tracked.txt"]
        self.assertNotEqual(target["source_sha256"], target["index_sha256"])
        self.assertNotEqual(target["index_sha256"], target["current_sha256"])
        self.assertEqual(target["source_index_state"], "MODIFIED_IN_INDEX")
        self.assertEqual(
            target["worktree_state"],
            "CONTENT_OR_TYPE_CHANGED_AGAINST_INDEX",
        )

    def test_gitlink_source_and_index_references_round_trip(self) -> None:
        repo, source, output = self.create_clean_repository("gitlink-present")
        run_git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            source,
            "modules/in-repo",
        )
        run_git(repo, "commit", "-m", "gitlink reference")
        gitlink_source = run_git(repo, "rev-parse", "HEAD")

        ledger.generate_ledger(repo, gitlink_source, output)
        rows = {row["path"]: row for row in ledger.parse_ledger(output.read_bytes())}
        row = rows["modules/in-repo"]
        self.assertEqual(row["source_git_mode"], "160000")
        self.assertEqual(row["source_object_type"], "commit")
        self.assertEqual(row["source_git_blob_id"], source)
        self.assertEqual(row["index_git_mode"], "160000")
        self.assertEqual(row["index_git_blob_id"], source)
        self.assertEqual(
            row["source_content_kind"],
            "GITLINK_COMMIT_REFERENCE_UNVERIFIED",
        )
        self.assertEqual(
            row["index_content_kind"],
            "GITLINK_COMMIT_REFERENCE_UNVERIFIED",
        )
        self.assertEqual(row["source_index_state"], "IDENTICAL")
        self.assertEqual(row["worktree_state"], "DELETED_FROM_WORKTREE")
        ledger.verify_ledger(repo, gitlink_source, output)

        missing_repo, missing_source, missing_output = self.create_clean_repository(
            "gitlink-missing"
        )
        missing_oid = "f" * len(missing_source)
        object_probe = subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(missing_repo),
                "cat-file",
                "-e",
                f"{missing_oid}^{{commit}}",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=GIT_ENV,
        )
        self.assertNotEqual(object_probe.returncode, 0)
        run_git(
            missing_repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            missing_oid,
            "modules/external",
        )

        ledger.generate_ledger(missing_repo, missing_source, missing_output)
        missing_rows = {
            row["path"]: row for row in ledger.parse_ledger(missing_output.read_bytes())
        }
        missing_row = missing_rows["modules/external"]
        self.assertEqual(missing_row["source_tracked"], "false")
        self.assertEqual(missing_row["index_git_mode"], "160000")
        self.assertEqual(missing_row["index_git_blob_id"], missing_oid)
        self.assertEqual(
            missing_row["index_content_kind"],
            "GITLINK_COMMIT_REFERENCE_UNVERIFIED",
        )
        self.assertEqual(missing_row["worktree_state"], "DELETED_FROM_WORKTREE")
        ledger.verify_ledger(missing_repo, missing_source, missing_output)

    def test_source_gitlink_size_field_uses_exact_padded_grammar(self) -> None:
        oid = self.source.encode("ascii")

        def record(mode: bytes, object_type: bytes, raw_size: bytes) -> bytes:
            return (
                mode
                + b" "
                + object_type
                + b" "
                + oid
                + b" "
                + raw_size
                + b"\tmodules/example\0"
            )

        padded = record(b"160000", b"commit", b"      -")
        with mock.patch.object(ledger, "_run_git", return_value=padded):
            entries = ledger._source_entries(
                self.repo,
                self.source,
                deadline=ledger.Deadline.after(10.0),
            )
        self.assertIsNone(entries["modules/example"].size)

        malformed = (
            record(b"160000", b"commit", b"-"),
            record(b"160000", b"commit", b"     -"),
            record(b"160000", b"commit", b"       -"),
            record(b"160000", b"commit", b"     - "),
            record(b"160000", b"commit", b"    BAD"),
            record(b"160000", b"commit", b"      1"),
            record(b"100644", b"blob", b"      -"),
        )
        for raw in malformed:
            with self.subTest(raw=raw):
                with mock.patch.object(ledger, "_run_git", return_value=raw):
                    with self.assertRaises(ledger.LedgerError):
                        ledger._source_entries(
                            self.repo,
                            self.source,
                            deadline=ledger.Deadline.after(10.0),
                        )

    def test_zero_oid_index_gitlink_is_rejected(self) -> None:
        raw = b"H 160000 " + b"0" * len(self.source) + b" 0\tmodules/zero-object\0"
        with mock.patch.object(ledger, "_run_git", return_value=raw):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "invalid index object identity",
            ):
                ledger._index_entries(
                    self.repo,
                    deadline=ledger.Deadline.after(10.0),
                )

    def test_signed_commit_continuations_do_not_forge_parent_headers(self) -> None:
        tree = run_git(self.repo, "rev-parse", f"{self.source}^{{tree}}")
        payload = (
            f"tree {tree}\n"
            f"parent {self.source}\n"
            "author Ledger Test <ledger@example.invalid> 0 +0000\n"
            "committer Ledger Test <ledger@example.invalid> 0 +0000\n"
            "gpgsig -----BEGIN PGP SIGNATURE-----\n"
            f" parent {'f' * len(self.source)}\n"
            " continuation-data\n"
            " -----END PGP SIGNATURE-----\n"
            "\n"
            "signed commit fixture\n"
        ).encode("ascii")
        object_format = "sha1" if len(self.source) == 40 else "sha256"
        oid = ledger._git_object_id(payload, "commit", object_format)
        self.assertEqual(
            ledger._parse_raw_commit_parents(
                payload,
                oid=oid,
                object_format=object_format,
            ),
            (self.source,),
        )

    def test_intent_to_add_and_extended_index_flags_are_rejected(self) -> None:
        candidate = self.repo / "intent.txt"
        candidate.write_text("intent\n", encoding="utf-8")
        run_git(self.repo, "add", "--intent-to-add", "intent.txt")
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "non-default|extended|invalid index",
        ):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )

    def test_independent_walk_rejects_git_omission(self) -> None:
        original_walk = ledger.SecureRepository.walk_leaf_paths

        def add_unclassified(
            secure: ledger.SecureRepository,  # type: ignore[name-defined]
            *,
            index_gitlinks: set[str],
            max_nodes: int,
            deadline: ledger.Deadline,  # type: ignore[name-defined]
        ) -> tuple[list[str], int]:
            paths, count = original_walk(
                secure,
                index_gitlinks=index_gitlinks,
                max_nodes=max_nodes,
                deadline=deadline,
            )
            return [*paths, "ghost-omitted-by-git"], count + 1

        with mock.patch.object(
            ledger.SecureRepository,
            "walk_leaf_paths",
            new=add_unclassified,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "omitted by Git classification",
            ):
                ledger.build_inventory(
                    self.repo,
                    self.source,
                    ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                    ignored_policy="inventory",
                )

    def test_ignored_policy_defaults_to_reject_and_records_exact_rule(self) -> None:
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "explicit inventory policy",
        ):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
            )
        rows = {
            row["path"]: row
            for row in ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )
        }
        ignored = rows["build/generated.bin"]
        self.assertTrue(ignored["ignore_rule_source"].endswith(".gitignore:1"))
        self.assertEqual(ignored["ignore_pattern"], "build/")

    def test_generated_defaults_require_frozen_positive_proof(self) -> None:
        self.generate()
        rows = self.rows()
        self.assertEqual(rows["tracked.txt"]["generated"], "UNKNOWN")
        self.assertEqual(rows["tracked.txt"]["generator"], "")
        self.assertEqual(
            rows["audit/FILE_REVIEW_LEDGER.csv"]["generated"],
            "YES",
        )
        self.assertEqual(
            rows["audit/FILE_REVIEW_LEDGER.csv"]["generator"],
            "tools/release/current-file-review-ledger.py",
        )
        for row in rows.values():
            if row["generated"] != "YES":
                self.assertNotEqual(row["generated"], "YES")
                self.assertEqual(row["generator"], "")

    def test_rule_proven_generated_yes_cannot_evolve_to_no(self) -> None:
        self.generate()
        rows = ledger.parse_ledger(self.output.read_bytes())
        self_row = next(
            row for row in rows if row["path"] == "audit/FILE_REVIEW_LEDGER.csv"
        )
        self.assertEqual(self_row["generated"], "YES")
        self_row["generated"] = "NO"
        self_row["generator"] = ""
        self.write_rows(rows)

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "rule-proven generated classification changed",
        ):
            self.verify()

    def test_reviewed_rows_may_retain_recorded_defects(self) -> None:
        self.generate()
        rows = ledger.parse_ledger(self.output.read_bytes())
        self.complete_reviews(rows)
        target = next(row for row in rows if row["path"] == "tracked.txt")
        target["defects"] = "DEF-001;resolved;review/evidence/DEF-001"
        self.write_rows(rows)
        verified = self.verify(require_reviewed=True)
        self.assertEqual(verified["rows"], len(rows))
        self.assertEqual(self.rows()["tracked.txt"]["defects"], target["defects"])

    def test_review_gate_rejects_adverse_or_incomplete_dispositions(self) -> None:
        self.generate()
        rows = ledger.parse_ledger(self.output.read_bytes())
        self.complete_reviews(rows)
        target = next(row for row in rows if row["path"] == "tracked.txt")
        target["disposition"] = "REJECTED"
        self.write_rows(rows)
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "non-accepting disposition",
        ):
            self.verify(require_reviewed=True)

    def test_unknown_generated_resolution_requires_completed_provenance(
        self,
    ) -> None:
        self.generate()
        rows = ledger.parse_ledger(self.output.read_bytes())
        target = next(row for row in rows if row["path"] == "tracked.txt")
        target["generated"] = "NO"
        self.write_rows(rows)
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "evidence-backed completed review",
        ):
            self.verify()

        rows = ledger.parse_ledger(self.output.read_bytes())
        self.complete_reviews(rows)
        self.write_rows(rows)
        self.verify(require_reviewed=True)

    def test_immutable_identity_tamper_is_rejected(self) -> None:
        self.generate()
        rows = ledger.parse_ledger(self.output.read_bytes())
        target = next(row for row in rows if row["path"] == "tracked.txt")
        target["current_sha256"] = "0" * 64
        self.write_rows(rows)
        with self.assertRaisesRegex(ledger.LedgerError, "immutable field mismatch"):
            self.verify()

    def test_duplicate_header_key_and_noncanonical_encoding_are_rejected(
        self,
    ) -> None:
        data = self.generate()
        header, remainder = data.split(b"\n", 1)
        names = header.decode("utf-8").split(",")
        names[0] = names[1]
        forged = (",".join(names) + "\n").encode("utf-8") + remainder
        with self.assertRaisesRegex(ledger.LedgerError, "duplicate keys"):
            ledger.parse_ledger(forged)
        with self.assertRaisesRegex(ledger.LedgerError, "canonical encoding"):
            ledger.parse_ledger(data.replace(b"\n", b"\r\n"))

    def test_every_mutable_cell_enforces_unicode_and_byte_grammar(self) -> None:
        controls = (
            "\t",
            "\n",
            "\r",
            "\x1b",
            "\x7f",
            "\u0085",
            "\u00ad",
            "\u202e",
            "\ue000",
            "\u0378",
        )
        for field in sorted(ledger.MUTABLE_FIELDS):
            with self.subTest(field=field, rule="byte-bound"):
                limit = ledger.FIELD_BYTE_LIMITS[field]
                ledger._validate_cell(field, "a" * limit, row_number=2)
                with self.assertRaisesRegex(ledger.LedgerError, "exceeds"):
                    ledger._validate_cell(
                        field,
                        "a" * (limit + 1),
                        row_number=2,
                    )
            with self.subTest(field=field, rule="nfc"):
                with self.assertRaisesRegex(ledger.LedgerError, "Unicode NFC"):
                    ledger._validate_cell(field, "e\u0301", row_number=2)
            with self.subTest(field=field, rule="strict-utf8"):
                with self.assertRaisesRegex(ledger.LedgerError, "strict UTF-8"):
                    ledger._validate_cell(field, "\ud800", row_number=2)
            for value in controls:
                with self.subTest(field=field, codepoint=f"U+{ord(value):04X}"):
                    with self.assertRaisesRegex(
                        ledger.LedgerError,
                        "Unicode category-C",
                    ):
                        ledger._validate_cell(field, value, row_number=2)

    def test_category_rules_have_explicit_test_basename_precedence(self) -> None:
        reason = "NONE_OBSERVED_REVIEW_REQUIRED"
        for path in (
            "tools/release/test_current_file_review_ledger.py",
            "tools/test_live_secure_zenoh.py",
            "crates/haldir-deployment/src/tests.rs",
            "web/component.spec.tsx",
            "src/parser_tests.rs",
        ):
            with self.subTest(path=path):
                self.assertEqual(ledger._category(path, reason), "TEST")
        self.assertEqual(
            ledger._category(
                "tools/release/current-file-review-ledger.py",
                reason,
            ),
            "TOOLING",
        )
        self.assertEqual(
            ledger._category("crates/haldir-core/src/lib.rs", reason),
            "RUST_SOURCE",
        )

    def test_duplicate_traversal_git_admin_and_case_paths_are_rejected(
        self,
    ) -> None:
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
                    ledger.LedgerError,
                    "administrative storage",
                ):
                    ledger._validate_path(path)
        with self.assertRaisesRegex(ledger.LedgerError, "case path collision"):
            ledger._validate_unique_paths(["Alpha", "alpha"], label="test")

    def test_symlink_leaf_and_ancestor_are_never_followed(self) -> None:
        self.generate()
        alternate = self.repo / "alternate.csv"
        alternate.write_bytes(self.output.read_bytes())
        self.output.unlink()
        os.symlink("../alternate.csv", self.output)
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "regular file, not a symlink",
        ):
            self.verify()

        repo, source, output = self.create_clean_repository("ancestor")
        external = self.root / "ancestor-external"
        external.mkdir()
        os.symlink(external, repo / "audit")
        with self.assertRaisesRegex(ledger.LedgerError, "unsafe|parent"):
            ledger.generate_ledger(repo, source, output)
        self.assertFalse((external / output.name).exists())

    def test_removed_tracked_parent_is_recorded_as_deletion(self) -> None:
        (self.repo / "nested" / "item.txt").unlink()
        (self.repo / "nested").rmdir()
        self.generate()
        row = self.rows()["nested/item.txt"]
        self.assertEqual(row["current_fs_type"], "")
        self.assertEqual(row["worktree_state"], "DELETED_FROM_WORKTREE")

    def test_regular_type_swap_to_fifo_never_blocks_open(self) -> None:
        def run_swap(
            target: Path,
            expected_name: str,
            operation: Callable[[], None],
        ) -> None:
            original_open = ledger._open_interrupt_safe
            swapped = False
            errors: list[BaseException] = []

            def swap_before_open(
                path: str | bytes | Path,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> object:
                nonlocal swapped
                if os.fsdecode(path) == expected_name and not swapped:
                    target.unlink()
                    os.mkfifo(target, 0o644)
                    swapped = True
                    self.assertNotEqual(flags & getattr(os, "O_NONBLOCK", 0), 0)
                return cast(
                    object,
                    original_open(path, flags, mode, dir_fd=dir_fd),
                )

            def invoke() -> None:
                try:
                    operation()
                except BaseException as exc:
                    errors.append(exc)

            with mock.patch.object(
                ledger,
                "_open_interrupt_safe",
                new=swap_before_open,
            ):
                worker = threading.Thread(target=invoke, daemon=True)
                worker.start()
                worker.join(timeout=2.0)
                blocked = worker.is_alive()
                if blocked:
                    rescue = os.open(target, os.O_RDWR | os.O_NONBLOCK)
                    os.close(rescue)
                    worker.join(timeout=2.0)

            self.assertFalse(blocked, "writerless FIFO open exceeded the join bound")
            self.assertTrue(swapped)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ledger.LedgerError)
            self.assertTrue(stat.S_ISFIFO(target.lstat().st_mode))

        def read_worktree_entry() -> None:
            with ledger.SecureRepository(self.repo) as secure:
                secure.read_entry(
                    "tracked.txt",
                    object_format=run_git(
                        self.repo,
                        "rev-parse",
                        "--show-object-format",
                    ),
                    max_file_bytes=1024,
                    budget=ledger.ByteBudget(1024),
                    deadline=ledger.Deadline.after(10.0),
                )

        run_swap(self.repo / "tracked.txt", "tracked.txt", read_worktree_entry)

        pin_repo, _source, pin_output = self.create_clean_repository("fifo-pin")
        pin_output.parent.mkdir()
        pin_output.write_bytes(b"ledger-like bytes\n")
        pin_output.chmod(0o644)

        def pin_ledger_entry() -> None:
            with ledger.SecureRepository(pin_repo) as secure:
                with secure.pin_regular(
                    "audit/FILE_REVIEW_LEDGER.csv",
                    maximum=1024,
                    deadline=ledger.Deadline.after(10.0),
                ):
                    pass

        run_swap(
            pin_output,
            "FILE_REVIEW_LEDGER.csv",
            pin_ledger_entry,
        )

    def test_regular_inventory_read_rejects_path_change(self) -> None:
        original_read = os.read
        competing = self.repo / "tracked-competing.tmp"
        competing.write_text("competing inode\n", encoding="utf-8")
        changed = False

        def read_then_change(descriptor: int, count: int) -> bytes:
            nonlocal changed
            data = original_read(descriptor, count)
            if not changed:
                changed = True
                os.replace(competing, self.repo / "tracked.txt")
            return data

        with (
            ledger.SecureRepository(self.repo) as secure,
            mock.patch.object(
                ledger.os,
                "read",
                side_effect=read_then_change,
            ),
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "file path changed while inventorying",
            ):
                secure.read_entry(
                    "tracked.txt",
                    object_format="sha1",
                    max_file_bytes=1024,
                    budget=ledger.ByteBudget(1024),
                    deadline=ledger.Deadline.after(10.0),
                )
        self.assertTrue(changed)
        self.assertEqual(
            (self.repo / "tracked.txt").read_text(encoding="utf-8"),
            "competing inode\n",
        )

    def test_pin_regular_rejects_same_size_mode_distinct_inode_replacement(
        self,
    ) -> None:
        target = self.repo / "tracked.txt"
        target.write_bytes(b"OLD0")
        target.chmod(0o644)
        initial_inode = target.stat().st_ino
        competing = self.repo / "same-size-competing.tmp"
        competing.write_bytes(b"NEW0")
        competing.chmod(0o644)
        self.assertNotEqual(initial_inode, competing.stat().st_ino)
        original_stat = ledger.os.stat
        path_stats = 0

        def stat_and_replace(
            path: object,
            *arguments: object,
            **keywords: object,
        ) -> os.stat_result:
            nonlocal path_stats
            if path == "tracked.txt" and keywords.get("dir_fd") is not None:
                path_stats += 1
                if path_stats == 2:
                    os.replace(competing, target)
            return cast(os.stat_result, original_stat(path, *arguments, **keywords))

        with (
            ledger.SecureRepository(self.repo) as secure,
            mock.patch.object(
                ledger.os,
                "stat",
                side_effect=stat_and_replace,
            ),
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "ledger path changed while reading",
            ):
                secure.pin_regular(
                    "tracked.txt",
                    maximum=1024,
                    deadline=ledger.Deadline.after(10.0),
                )
        self.assertEqual(target.read_bytes(), b"NEW0")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.assertNotEqual(target.stat().st_ino, initial_inode)

    def test_resource_bounds_fail_closed(self) -> None:
        self.assertEqual(ledger.MAX_LEDGER_BYTES, 4 * 1024 * 1024)
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

    def test_walk_total_byte_and_parse_row_bounds_are_exact(self) -> None:
        with ledger.SecureRepository(self.repo) as secure:
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "filesystem walk exceeds node limit 1",
            ):
                secure.walk_leaf_paths(
                    index_gitlinks=set(),
                    max_nodes=1,
                    deadline=ledger.Deadline.after(10.0),
                )

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "content byte budget exceeded",
        ):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
                max_total_bytes=1,
            )

        rows = ledger.build_inventory(
            self.repo,
            self.source,
            ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
            ignored_policy="inventory",
        )
        limit = len(rows)
        exact = ledger.render_ledger(rows)
        self.assertEqual(len(ledger.parse_ledger(exact, max_rows=limit)), limit)
        extra = dict(rows[-1])
        extra["path"] = "zz-row-limit-extra"
        over_limit = ledger.render_ledger([*rows, extra])
        with self.assertRaisesRegex(
            ledger.LedgerError,
            f"ledger exceeds row limit {limit}",
        ):
            ledger.parse_ledger(over_limit, max_rows=limit)

    def test_bounded_integer_types_and_render_schema_are_exact(self) -> None:
        for value in (True, 1.0, "1", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ledger.LedgerError,
                    "must be an integer",
                ):
                    ledger._bounded_int(
                        cast(Any, value),
                        name="mutation bound",
                        lower=1,
                        upper=10,
                    )

        rows = ledger.build_inventory(
            self.repo,
            self.source,
            ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
            ignored_policy="inventory",
        )
        missing = [dict(row) for row in rows]
        missing[0].pop("assumptions")
        extra = [dict(row) for row in rows]
        extra[0]["unexpected"] = "value"
        for malformed in (missing, extra):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "does not exactly match the ledger schema",
            ):
                ledger.render_ledger(malformed)

    def test_chunk_read_deadline_is_checked_before_every_read(self) -> None:
        target = self.repo / "chunk-deadline.csv"
        target.write_bytes(b"one bounded chunk")
        target.chmod(0o644)
        descriptor = os.open(target, os.O_RDONLY)
        original_check = ledger.Deadline.check
        original_read = os.read
        read_checks = 0
        reads = 0

        def fail_second_read_check(
            deadline: ledger.Deadline,  # type: ignore[name-defined]
            label: str,
        ) -> None:
            nonlocal read_checks
            if label.startswith("reading ledger"):
                read_checks += 1
                if read_checks == 2:
                    raise ledger.LedgerError("injected chunk-read deadline")
            original_check(deadline, label)

        def count_reads(fd: int, maximum: int) -> bytes:
            nonlocal reads
            if fd == descriptor:
                reads += 1
            return original_read(fd, maximum)

        try:
            with (
                mock.patch.object(
                    ledger.Deadline,
                    "check",
                    new=fail_second_read_check,
                ),
                mock.patch.object(ledger.os, "read", side_effect=count_reads),
            ):
                with self.assertRaisesRegex(
                    ledger.LedgerError,
                    "injected chunk-read deadline",
                ):
                    ledger.SecureRepository._snapshot_descriptor(
                        descriptor,
                        label=repr(target),
                        maximum=1024,
                        deadline=ledger.Deadline.after(10.0),
                    )
        finally:
            os.close(descriptor)

        self.assertEqual(read_checks, 2)
        self.assertEqual(reads, 1)

    def test_git_output_bounds_and_toplevel_parser_fail_closed(self) -> None:
        malformed = (
            b"relative/path\n",
            b"/absolute/without-newline",
            b"/two\nlines\n",
            b"/nul\0path\n",
            b"/invalid-\xff\n",
            b"/" + b"a" * ledger.MAX_PATH_BYTES + b"\n",
        )
        for raw in malformed:
            with self.subTest(raw=raw[:32]):
                with self.assertRaises(ledger.LedgerError):
                    ledger._parse_git_toplevel(raw)

        with self.assertRaisesRegex(ledger.LedgerError, "stdout exceeded 1 bytes"):
            ledger._run_git(
                self.repo,
                ["rev-parse", "--show-toplevel"],
                max_stdout=1,
                deadline=ledger.Deadline.after(10.0),
            )

        with mock.patch.object(ledger, "MAX_GIT_STDERR_BYTES", 1):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "stderr exceeded 1 bytes",
            ):
                ledger._run_git(
                    self.repo,
                    ["rev-parse", "--verify", "definitely-missing-object"],
                    deadline=ledger.Deadline.after(10.0),
                )

        malformed_batch = f"{self.source} commit 3\nabc".encode("ascii")
        with mock.patch.object(ledger, "_run_git", return_value=malformed_batch):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "truncated Git cat-file commit payload",
            ):
                ledger._raw_commit_parent_map(
                    self.repo,
                    [self.source],
                    deadline=ledger.Deadline.after(10.0),
                )

    def test_git_timeout_kills_and_reaps_child_process(self) -> None:
        original_popen = subprocess.Popen
        captured: list[subprocess.Popen[bytes]] = []

        def capture_process(
            *arguments: Any,
            **keywords: Any,
        ) -> subprocess.Popen[bytes]:
            process = original_popen(*arguments, **keywords)
            captured.append(process)
            return process

        sleeper = [
            sys.executable,
            "-I",
            "-c",
            "import time; time.sleep(30)",
        ]
        with (
            mock.patch.object(ledger, "_git_command", return_value=sleeper),
            mock.patch.object(
                ledger.subprocess,
                "Popen",
                side_effect=capture_process,
            ),
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "Git command timed out",
            ):
                ledger._run_git(
                    self.repo,
                    ["timeout-fixture"],
                    timeout=0.05,
                )

        self.assertEqual(len(captured), 1)
        self.assertIsNotNone(captured[0].poll())

    def test_unterminated_nul_and_index_view_mismatches_fail_closed(self) -> None:
        with self.assertRaisesRegex(ledger.LedgerError, "unterminated NUL-delimited"):
            ledger._parse_z_paths(b"unterminated", label="mutation fixture")

        stage = f"H 100644 {self.source} 0\ttracked.txt\0".encode("ascii")
        fsmonitor = b"H tracked.txt\0"

        def debug(path: str) -> bytes:
            return path.encode("ascii") + (
                b"\0"
                b"  ctime: 0:0\n"
                b"  mtime: 0:0\n"
                b"  dev: 0\tino: 0\n"
                b"  uid: 0\tgid: 0\n"
                b"  size: 0\tflags: 0\n"
            )

        with mock.patch.object(ledger, "_run_git", return_value=stage[:-1]):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "unterminated git ls-files --stage output",
            ):
                ledger._index_entries(
                    self.repo,
                    deadline=ledger.Deadline.after(10.0),
                )

        with mock.patch.object(
            ledger,
            "_run_git",
            side_effect=(stage, b"H other.txt\0"),
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "index views disagree",
            ):
                ledger._index_entries(
                    self.repo,
                    deadline=ledger.Deadline.after(10.0),
                )

        for malformed_debug, message in (
            (debug("other.txt"), "debug index view disagrees on path ordering"),
            (debug("tracked.txt") + b"x", "unexpected trailing data"),
        ):
            with self.subTest(message=message):
                with mock.patch.object(
                    ledger,
                    "_run_git",
                    side_effect=(stage, fsmonitor, malformed_debug),
                ):
                    with self.assertRaisesRegex(ledger.LedgerError, message):
                        ledger._index_entries(
                            self.repo,
                            deadline=ledger.Deadline.after(10.0),
                        )

        with mock.patch.object(
            ledger,
            "_run_git_input",
            return_value=b"\0".join((b".gitignore", b"1", b"build/", b"build/item")),
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "unterminated git check-ignore output",
            ):
                ledger._ignored_rule_records(
                    self.repo,
                    ["build/item"],
                    deadline=ledger.Deadline.after(10.0),
                )

    def test_check_ignore_input_bound_and_contradiction_are_deterministic(self) -> None:
        oversized = b"x" * (4 * 1024 * 1024 + 1)
        with mock.patch.object(ledger.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "Git stdin chunk exceeds 4 MiB",
            ):
                ledger._run_git_input(
                    self.repo,
                    ["check-ignore", "-z", "-v", "--stdin"],
                    oversized,
                    max_stdout=1024,
                    deadline=ledger.Deadline.after(10.0),
                )
            popen.assert_not_called()

        path = "a" * ledger.FIELD_BYTE_LIMITS["path"]
        line = b"1" * ledger.MAX_DECIMAL_CELL_BYTES
        source = b"s" * (ledger.FIELD_BYTE_LIMITS["ignore_rule_source"] - 1 - len(line))
        pattern = b"p" * ledger.FIELD_BYTE_LIMITS["ignore_pattern"]
        exact = b"\0".join((source, line, pattern, path.encode("ascii"))) + b"\0"
        one_over = (
            b"\0".join((source, line, pattern + b"x", path.encode("ascii"))) + b"\0"
        )
        self.assertEqual(len(exact), ledger._CHECK_IGNORE_RECORD_MAX_BYTES)
        self.assertEqual(len(one_over), len(exact) + 1)
        rows_to_cap = (
            ledger.MAX_GIT_INVENTORY_BYTES // ledger._CHECK_IGNORE_RECORD_MAX_BYTES + 1
        )
        self.assertEqual(
            ledger._check_ignore_stdout_bound(rows_to_cap),
            ledger.MAX_GIT_INVENTORY_BYTES,
        )
        responses = [exact, one_over]
        observed_bounds: list[int] = []

        def enforce_supplied_bound(
            *_arguments: object,
            **keywords: object,
        ) -> bytes:
            maximum = cast(int, keywords["max_stdout"])
            observed_bounds.append(maximum)
            response = responses.pop(0)
            if len(response) > maximum:
                raise ledger.LedgerError("synthetic check-ignore stdout exceeded bound")
            return response

        with mock.patch.object(
            ledger,
            "_run_git_input",
            side_effect=enforce_supplied_bound,
        ):
            records = ledger._ignored_rule_records(
                self.repo,
                [path],
                deadline=ledger.Deadline.after(10.0),
            )
            self.assertEqual(
                records[path],
                (f"{source.decode()}:{line.decode()}", pattern.decode()),
            )
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "stdout exceeded bound",
            ):
                ledger._ignored_rule_records(
                    self.repo,
                    [path],
                    deadline=ledger.Deadline.after(10.0),
                )

        self.assertEqual(
            observed_bounds,
            [ledger._CHECK_IGNORE_RECORD_MAX_BYTES] * 2,
        )

        contradictory = (
            b"\0".join((b".gitignore", b"1", b"build/", b"wrong/path")) + b"\0"
        )
        with mock.patch.object(
            ledger,
            "_run_git_input",
            return_value=contradictory,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError,
                "contradictory classification",
            ):
                ledger._ignored_rule_records(
                    self.repo,
                    ["build/generated.bin"],
                    deadline=ledger.Deadline.after(10.0),
                )

    def test_content_classification_and_digest_domains_are_strict(self) -> None:
        self.assertEqual(
            ledger._classify_content(b"a\rb\rc\r"),
            ("TEXT_UTF8", 3),
        )
        self.assertEqual(
            ledger._classify_content(b"\x1b[31mred\x1b[0m\n"),
            ("TEXT_UTF8_WITH_ANSI_ESCAPE", 1),
        )
        for payload in (
            b"delete:\x7f",
            "c1:\u0085".encode(),
            "bidi:\u202e".encode(),
            "soft-hyphen:\u00ad".encode(),
        ):
            with self.subTest(payload=payload):
                self.assertEqual(
                    ledger._classify_content(payload)[0],
                    "TEXT_UTF8_WITH_CONTROLS",
                )
        self.assertNotEqual(
            ledger._canonical_digest("source", [{"path": "a"}]),
            ledger._canonical_digest("index", [{"path": "a"}]),
        )
        with self.assertRaisesRegex(ledger.LedgerError, "full lowercase"):
            ledger.build_inventory(
                self.repo,
                self.source[:12],
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )

    def test_git_configuration_and_process_environment_are_isolated(self) -> None:
        malicious = self.root / "malicious-index"
        malicious.write_bytes(b"not an index")
        with mock.patch.dict(
            os.environ,
            {
                "GIT_DIR": str(self.root / "not-a-repository"),
                "GIT_INDEX_FILE": str(malicious),
                "GIT_OBJECT_DIRECTORY": str(self.root / "objects"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.hooksPath",
                "GIT_CONFIG_VALUE_0": str(self.root),
            },
            clear=False,
        ):
            rows = ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )
        self.assertGreater(len(rows), 1)

    def test_repository_argument_must_equal_exact_git_toplevel(self) -> None:
        root_rows = ledger.build_inventory(
            self.repo,
            self.source,
            ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
            ignored_policy="inventory",
        )
        self.assertGreater(len(root_rows), 1)

        with self.assertRaisesRegex(
            ledger.LedgerError,
            "must equal Git's exact top-level",
        ):
            ledger.build_inventory(
                self.repo / "nested",
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )

    def test_repository_binding_accepts_ancestor_alias_but_rejects_leaf_symlink(
        self,
    ) -> None:
        physical_parent = self.root / "physical-parent"
        physical_parent.mkdir()
        physical_repo, source, _physical_output = self.create_clean_repository(
            "physical-parent/repo"
        )
        alias_parent = self.root / "alias-parent"
        os.symlink(physical_parent, alias_parent)
        alias_repo = alias_parent / physical_repo.name
        alias_output = alias_repo / "audit" / "FILE_REVIEW_LEDGER.csv"

        generated = ledger.generate_ledger(alias_repo, source, alias_output)
        verified = ledger.verify_ledger(alias_repo, source, alias_output)
        self.assertEqual(verified["ledger_sha256"], generated["ledger_sha256"])
        self.assertEqual(alias_repo.resolve(), physical_repo.resolve())
        self.assertTrue(alias_output.is_file())

        leaf_alias = self.root / "repository-leaf-link"
        os.symlink(self.repo, leaf_alias)
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "repository root argument is not a real directory",
        ):
            ledger.build_inventory(
                leaf_alias,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )

    def test_format_is_content_aware_and_ansi_logs_preserve_lines(self) -> None:
        ansi = self.repo / "session.log"
        ansi.write_bytes(b"\x1b[31mred\x1b[0m\nplain\n")
        rows = {
            row["path"]: row
            for row in ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )
        }
        row = rows["session.log"]
        self.assertEqual(row["format"], "ANSI_LOG_TEXT")
        self.assertEqual(row["current_content_kind"], "TEXT_UTF8_WITH_ANSI_ESCAPE")
        self.assertEqual(row["current_lines"], "2")

    def test_cli_round_trip_and_review_gate_exit_codes(self) -> None:
        generate_command = [
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
        ]
        generated = subprocess.run(
            generate_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(generated.returncode, 0, generated.stderr)
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
        verified = subprocess.run(
            verify_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        assigned = subprocess.run(
            [*verify_command, "--require-assigned"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(assigned.returncode, 2)
        self.assertIn("reviewer is not assigned", assigned.stderr)
        reviewed = subprocess.run(
            [*verify_command, "--require-reviewed"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(reviewed.returncode, 2)
        self.assertIn("reviewer is not assigned", reviewed.stderr)
        repeated = subprocess.run(
            generate_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(repeated.returncode, 2)
        self.assertIn("already exists", repeated.stderr)
        unsupported = subprocess.run(
            [*generate_command, "--replace"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(unsupported.returncode, 2)
        self.assertIn("unrecognized arguments", unsupported.stderr)
        nonisolated = subprocess.run(
            [item for item in verify_command if item != "-I"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(nonisolated.returncode, 2)
        self.assertIn("isolated safe-path mode", nonisolated.stderr)

    def test_cli_retention_verifies_exact_implementation_commit(self) -> None:
        repo, source, output, implementation = self.create_retention_repository(
            "cli-retention"
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(SCRIPT),
                "verify",
                "--repo",
                str(repo),
                "--source-commit",
                source,
                "--ledger",
                str(output),
                "--implementation-commit",
                implementation,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30.0,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["implementation_commit"], implementation)
        self.assertEqual(result["retained_head_commit"], implementation)
        self.assertEqual(
            result["verification_view"],
            "EXACT_IMPLEMENTATION_SNAPSHOT",
        )


if __name__ == "__main__":
    unittest.main()
