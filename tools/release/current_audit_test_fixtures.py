#!/usr/bin/env python3
"""Disposable, test-only fixtures for the current-head verifier.

Nothing in this module creates release evidence.  Its Git repositories, keys,
commits, and payloads live only in temporary directories and exist to exercise
the production verifier against real objects rather than repository mocks.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator, Mapping


GIT = "/usr/bin/git"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
AUTHOR_NAME = "Sepehr Mahmoudian"
AUTHOR_EMAIL = "sepmhn@gmail.com"


class TestFixtureError(RuntimeError):
    """A disposable fixture could not be created or verified."""


@dataclass(frozen=True)
class SignedRepository:
    """Paths and identity material for one isolated signed Git repository."""

    path: Path
    private_key: Path
    public_key: Path
    allowed_signers: Path


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def deterministic_gzip(payload: bytes) -> bytes:
    compressed = bytearray(gzip.compress(payload, compresslevel=9, mtime=0))
    compressed[9] = 3
    return bytes(compressed)


def file_record(path: str, payload: bytes) -> dict[str, object]:
    _safe_relative_path(path)
    return {
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "lines": len(payload.splitlines()),
    }


def protocol_blob_record(
    fixture: SignedRepository,
    path: str,
    payload: bytes,
    *,
    executable: bool = False,
) -> dict[str, object]:
    """Precompute the exact payload and Git identity record used by an F commit."""

    _safe_relative_path(path)
    oid = (
        _run(
            fixture.path,
            "hash-object",
            "-w",
            "--stdin",
            input_payload=payload,
        )
        .decode("ascii")
        .strip()
    )
    record = file_record(path, payload)
    record.update(
        {
            "git_mode": "100755" if executable else "100644",
            "git_object_type": "blob",
            "git_object_id": oid,
        }
    )
    if path.endswith((".json", ".py", ".sh", ".yml", ".md")) or path == "justfile":
        record["lines"] = len(payload.splitlines())
    return record


def _safe_relative_path(path: str) -> PurePosixPath:
    if not isinstance(path, str) or not path or "\\" in path:
        raise TestFixtureError("fixture path is not canonical")
    candidate = PurePosixPath(path)
    if (
        candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or candidate.as_posix() != path
    ):
        raise TestFixtureError("fixture path is not canonical")
    return candidate


def _environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    if overrides is not None:
        environment.update(overrides)
    return environment


def _run(
    repo: Path,
    *arguments: str,
    timeout: int = 30,
    environment: Mapping[str, str] | None = None,
    input_payload: bytes | None = None,
) -> bytes:
    result = subprocess.run(
        [GIT, "--no-replace-objects", "-C", str(repo), *arguments],
        input=input_payload,
        stdin=subprocess.DEVNULL if input_payload is None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
        env=_environment(environment),
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise TestFixtureError(f"Git fixture command failed: {detail}")
    return result.stdout


@contextmanager
def signed_repository(shared_root: Path | None = None) -> Iterator[SignedRepository]:
    """Yield an isolated repository whose commits use a fresh Ed25519 key."""

    container = Path(
        tempfile.mkdtemp(
            prefix="haldir-signed-fixture-",
            dir=None if shared_root is None else str(shared_root),
        )
    )
    repo = container / "repo"
    key = container / "signing-key"
    allowed_signers = container / "allowed-signers"
    try:
        key_result = subprocess.run(
            [SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            env=_environment(),
        )
        if key_result.returncode != 0:
            raise TestFixtureError("unable to generate fixture signing key")
        public_key = key.with_suffix(".pub")
        allowed_signers.write_text(
            AUTHOR_EMAIL + " " + public_key.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        repo.mkdir()
        _run(repo, "init", "--initial-branch=main")
        for key_name, value in (
            ("user.name", AUTHOR_NAME),
            ("user.email", AUTHOR_EMAIL),
            ("gpg.format", "ssh"),
            ("user.signingkey", str(key)),
            ("commit.gpgsign", "true"),
            ("gpg.ssh.allowedSignersFile", str(allowed_signers)),
        ):
            _run(repo, "config", "--local", key_name, value)
        yield SignedRepository(repo, key, public_key, allowed_signers)
    finally:
        shutil.rmtree(container, ignore_errors=True)


def signed_commit(
    fixture: SignedRepository,
    changes: Mapping[str, bytes | None],
    subject: str,
    *,
    executable_paths: frozenset[str] = frozenset(),
    allow_empty: bool = False,
    signed: bool = True,
    require_release_subject: bool = True,
    author_name: str = AUTHOR_NAME,
    author_email: str = AUTHOR_EMAIL,
    committer_name: str = AUTHOR_NAME,
    committer_email: str = AUTHOR_EMAIL,
) -> str:
    """Apply exact fixture changes and create one signed single-parent commit."""

    if (
        (require_release_subject and not subject.startswith("release: "))
        or "\n" in subject
        or not subject
    ):
        raise TestFixtureError("fixture commit subject is invalid")
    for raw_path, payload in changes.items():
        relative = _safe_relative_path(raw_path)
        target = fixture.path.joinpath(*relative.parts)
        if payload is None:
            if target.exists() or target.is_symlink():
                target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        mode = 0o755 if raw_path in executable_paths else 0o644
        os.chmod(target, mode, follow_symlinks=False)
    _run(fixture.path, "add", "--all", "--", ".")
    arguments = ["commit", "--signoff"]
    if signed:
        arguments.append("-S")
    else:
        arguments.append("--no-gpg-sign")
    arguments.extend(("-m", subject))
    if allow_empty:
        arguments.insert(1, "--allow-empty")
    _run(
        fixture.path,
        *arguments,
        environment={
            "GIT_AUTHOR_NAME": author_name,
            "GIT_AUTHOR_EMAIL": author_email,
            "GIT_COMMITTER_NAME": committer_name,
            "GIT_COMMITTER_EMAIL": committer_email,
        },
    )
    commit = _run(fixture.path, "rev-parse", "HEAD").decode("ascii").strip()
    if signed:
        verify_signed_commit(fixture, commit)
    return commit


def signed_merge_commit(
    fixture: SignedRepository,
    first_parent: str,
    second_parent: str,
    subject: str,
) -> str:
    """Create a signed, two-parent commit object for merge rejection tests."""

    if not subject.startswith("release: ") or "\n" in subject:
        raise TestFixtureError("fixture merge subject is invalid")
    tree = _run(fixture.path, "rev-parse", f"{first_parent}^{{tree}}")
    commit = (
        _run(
            fixture.path,
            "commit-tree",
            "-S",
            tree.decode("ascii").strip(),
            "-p",
            first_parent,
            "-p",
            second_parent,
            input_payload=(subject + "\n").encode("utf-8"),
        )
        .decode("ascii")
        .strip()
    )
    verify_signed_commit(fixture, commit)
    return commit


def verify_signed_commit(fixture: SignedRepository, commit: str) -> None:
    output = _run(
        fixture.path,
        "-c",
        f"gpg.ssh.allowedSignersFile={fixture.allowed_signers}",
        "-c",
        f"gpg.ssh.program={SSH_KEYGEN}",
        "-c",
        f"gpg.ssh.revocationFile={os.devnull}",
        "-c",
        "gpg.format=ssh",
        "verify-commit",
        commit,
    )
    if output:
        raise TestFixtureError("fixture signature verifier wrote unexpected stdout")


def detached_attestation(
    fixture: SignedRepository,
    payload: bytes,
    *,
    namespace: str,
    principal: str,
) -> dict[str, str]:
    """Sign one disposable payload and return the verifier's attestation shape."""

    payload_path = fixture.path.parent / "detached-payload"
    signature_path = payload_path.with_suffix(".sig")
    payload_path.write_bytes(payload)
    result = subprocess.run(
        [
            SSH_KEYGEN,
            "-Y",
            "sign",
            "-f",
            str(fixture.private_key),
            "-n",
            namespace,
            str(payload_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        env=_environment(),
    )
    if result.returncode != 0 or not signature_path.is_file():
        raise TestFixtureError("unable to create detached fixture signature")
    key_parts = fixture.public_key.read_text(encoding="utf-8").split()
    if len(key_parts) < 2:
        raise TestFixtureError("fixture public key is invalid")
    public_key = " ".join(key_parts[:2])
    key_result = subprocess.run(
        [SSH_KEYGEN, "-E", "sha256", "-lf", str(fixture.public_key)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        env=_environment(),
    )
    key_fields = (key_result.stdout + key_result.stderr).split()
    if key_result.returncode != 0 or len(key_fields) < 2:
        raise TestFixtureError("unable to fingerprint fixture public key")
    return {
        "format": "ssh",
        "namespace": namespace,
        "principal": principal,
        "public_key": public_key,
        "key_fingerprint": key_fields[1].decode("ascii"),
        "signature": signature_path.read_text(encoding="utf-8"),
    }


def first_parent_chain(fixture: SignedRepository) -> tuple[str, ...]:
    raw = _run(fixture.path, "rev-list", "--first-parent", "--reverse", "HEAD")
    chain = tuple(raw.decode("ascii").splitlines())
    if not chain:
        raise TestFixtureError("fixture chain is empty")
    return chain


def regular_mode(path: Path) -> str:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise TestFixtureError("fixture path is not a regular file")
    return f"{stat.S_IMODE(metadata.st_mode):06o}"
