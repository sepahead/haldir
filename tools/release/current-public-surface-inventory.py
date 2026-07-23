#!/usr/bin/env python3
"""Generate or verify the CH-T003 public-surface and claim inventory products.

The generate command reads a signed freeze commit. It does not use the mutable
worktree as source evidence. It reads only the candidate claim ledger, this
tool, and its tests from the worktree. The verify command reads the exact
implementation commit and calls the verifier that is registered in its parent
freeze commit.
"""

from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import csv
import fcntl
import gzip
import hashlib
import io
import json
import math
import os
import re
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import types
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence


TASK_ID = "CH-T003"
EPOCH = 1
RELEASE_TARGET = "0.9.0"
AUTHOR = {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"}
REPOSITORY = "sepahead/haldir"
NARROWED_CLAIM = "CL-PUBLICATION-EVIDENCE-PRIMITIVE-01"
NARROWED_CLAIM_STATEMENT = (
    "Repository VERIFIED evidence primitives do not establish VALIDATED, "
    "DEPLOYMENT_QUALIFIED, or FIELD_VALIDATED status, a release-qualified "
    "artifact, transport delivery, or operational use."
)
PRIOR_LIFECYCLE = {
    "freeze_commit": "b737cfa85d03c377be269498a2209ca873c3f906",
    "implementation_commit": "5f3d60c225c89ee05da11cecd1beaddd68f74ec8",
    "qualification_commit": "7a4e3f7d79ba5561ab961e374c4c38dbbd9d0f1b",
    "activation_commit": "590ba767b32a27d9dd61a2462968306c1052434e",
}

PUBLIC_INVENTORY_PATH = "audit/generated/CH-T003_PUBLIC_SURFACE_INVENTORY.json"
CLAIM_TIER_PATH = "audit/generated/CH-T003_CLAIM_TIER_LEDGER.json"
REVIEW_OVERLAY_PATH = "audit/generated/CH-T003_FILE_REVIEW_OVERLAY.json"
LEDGER_COMPOSITION_PATH = "audit/generated/CH-T003_LEDGER_COMPOSITION.json"
GITHUB_METADATA_PATH = "audit/generated/CH-T003_GITHUB_METADATA.json"
CLAIM_LANGUAGE_PATH = "audit/generated/CLAIM_LANGUAGE.json"
CLAIM_LEDGER_PATH = "docs/CLAIM-LEDGER.md"
PRODUCT_PATH = "tools/release/current-public-surface-inventory.py"
PRODUCT_TESTS_PATH = "tools/release/test_current_public_surface_inventory.py"
CLAIMS_STATE_PATH = "release/0.9.0/current-head/closures/active-claims.json"
ALLOWED_SIGNERS_PATH = "release/0.9.0/allowed-signers"
VERIFIER_REGISTRY_PATH = (
    "release/0.9.0/current-head/closures/task-verifier-registry.json"
)
FROZEN_VERIFIER_PATH = "tools/release/tasks/ch-t003/e0001/verify.py"
FROZEN_TESTS_PATH = "tools/release/tasks/ch-t003/e0001/test_verify.py"
FREEZE_CONTRACT_PATH = "release/0.9.0/current-head/tasks/ch-t003/e0001/freeze.json"
GIT_EXECUTABLE = "/usr/bin/git"
SSH_KEYGEN_EXECUTABLE = "/usr/bin/ssh-keygen"
EXPECTED_FREEZE_SUBJECT = "release: freeze CH-T003 verification protocol"
FREEZE_PLAN = {
    VERIFIER_REGISTRY_PATH: "M",
    FREEZE_CONTRACT_PATH: "A",
    FROZEN_TESTS_PATH: "A",
    FROZEN_VERIFIER_PATH: "A",
}

IMPLEMENTATION_PLAN = {
    CLAIM_TIER_PATH: "A",
    REVIEW_OVERLAY_PATH: "A",
    GITHUB_METADATA_PATH: "A",
    LEDGER_COMPOSITION_PATH: "A",
    PUBLIC_INVENTORY_PATH: "A",
    CLAIM_LANGUAGE_PATH: "A",
    CLAIM_LEDGER_PATH: "M",
    PRODUCT_PATH: "A",
    PRODUCT_TESTS_PATH: "A",
}
OUTPUT_PATHS = (
    PUBLIC_INVENTORY_PATH,
    CLAIM_TIER_PATH,
    REVIEW_OVERLAY_PATH,
    LEDGER_COMPOSITION_PATH,
    GITHUB_METADATA_PATH,
    CLAIM_LANGUAGE_PATH,
)

MAX_BLOB_BYTES = 4 * 1024 * 1024
MAX_AGGREGATE_BLOB_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4_096
MAX_COMPRESSION_RATIO = 100
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_PUBLIC_API_DOCUMENT_SET_BYTES = 2 * 1024 * 1024
MAX_HTTP_BODY_BYTES = 1 * 1024 * 1024
MAX_HTTP_TOTAL_BYTES = 16 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_TOOL_BINARY_BYTES = 256 * 1024 * 1024
MAX_PATH_BYTES = 240
MAX_TREE_ENTRIES = 8_192
MAX_GITHUB_PAGES = 100
MAX_LANGUAGE_HITS = 32_768
PUBLICATION_TRANSACTION_DIRECTORY = ".haldir-ch-t003-publication"
PUBLICATION_LOCK_FILE = ".haldir-ch-t003-publication.lock"
PUBLICATION_LOCK_PAYLOAD = b"haldir CH-T003 publication lock\n"
PUBLICATION_JOURNAL_STAGING = "journal.pending"
PUBLICATION_ACTIVE_MARKER = "active.json"
PUBLICATION_COMMITTED_MARKER = "committed.json"

NESTED_ARCHIVE_SUFFIXES = (
    ".7z",
    ".bz2",
    ".gz",
    ".gzip",
    ".rar",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.xz",
    ".tar.zst",
    ".tbz",
    ".tbz2",
    ".tgz",
    ".txz",
    ".xz",
    ".zip",
    ".zst",
)
ARCHIVE_MAGIC_PREFIXES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x1f\x8b\x08",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf'\x1c",
    b"Rar!\x1a\x07",
    b"\x28\xb5\x2f\xfd",
)

PINNED_RUST_VERSION = "1.96.0"
PINNED_CARGO_PUBLIC_API_VERSION = "0.52.0"
PINNED_ZIG_VERSION = "0.16.0"
PINNED_ZIG_SHA256 = "71cc3995a7586753ebf82c66dfb8bef43df446517550678781834586a960f8c9"
RUST_TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu")
EXPECTED_EXPORTED_MACROS = (
    "__hc_build",
    "__hc_count",
    "__hc_encode",
    "__hc_field_ty",
    "__hc_raw_ty",
    "canonical_struct",
    "tagged_enum",
)

TIER_VOCABULARY = (
    "IMPLEMENTED",
    "VERIFIED",
    "VALIDATED",
    "DEPLOYMENT_QUALIFIED",
    "FIELD_VALIDATED",
    "NOT_CLAIMED",
)
CLAIM_STATUSES = {
    "PROVEN",
    "PARTIAL",
    "PENDING",
    "UNPROVEN",
    "OUT OF SCOPE",
    "REMOVED",
    "NOT_CLAIMED",
}
CLAIM_ID_PATTERN = re.compile(r"\bCL-[A-Z0-9]+(?:-[A-Z0-9]+)+\b")
BASELINE_PATTERN_TEXT = (
    r"(?i)\b(safe|secure|verified|validated|production[- ]ready|field[- ]tested|"
    r"exact|identical|complete|correct|real[- ]time|certified|compatible|stable|"
    r"proven|guarantee)\b"
)
BASELINE_PATTERN = re.compile(BASELINE_PATTERN_TEXT)
EXTENDED_PATTERN_TEXT = (
    r"(?i)\b(airworthy|certified|complete(?: mediation)?|correct|deployment|"
    r"exact(?:ly once)?|field[- ](?:tested|validated)|guarantee|identical|"
    r"production[- ]ready|proven|real[- ]time|release[- ]qualified|safe|secure|"
    r"stable|validated|verified)\b"
)
EXTENDED_PATTERN = re.compile(EXTENDED_PATTERN_TEXT)

REGULAR_MODES = {"100644", "100755"}
PUBLIC_CLASSIFICATIONS = {
    "PUBLIC_DOCUMENTATION",
    "PUBLIC_API_OR_SCHEMA",
    "BUILD_OR_DEPLOYMENT",
}
EXCLUDED_CLASSIFICATIONS = {
    "EXCLUDED_INTERNAL_EVIDENCE_OR_RELEASE",
    "EXCLUDED_INTERNAL_TEST_OR_TOOL",
    "EXCLUDED_NONINTERFACE_ASSET",
}
ALL_CLASSIFICATIONS = PUBLIC_CLASSIFICATIONS | EXCLUDED_CLASSIFICATIONS

KNOWN_SUFFIXES = {
    "",
    ".cfg",
    ".cbor",
    ".csv",
    ".dockerignore",
    ".gz",
    ".hex",
    ".ico",
    ".json",
    ".json5",
    ".lock",
    ".log",
    ".md",
    ".pdf",
    ".png",
    ".proto",
    ".py",
    ".rst",
    ".rs",
    ".sh",
    ".sha256",
    ".svg",
    ".tla",
    ".toml",
    ".txt",
    ".wasm",
    ".yaml",
    ".yml",
    ".zip",
}


class InventoryError(RuntimeError):
    """A deterministic generation failure."""


class GeneratedProducts(dict[str, Any]):
    """Generated product values with their immutable candidate-input snapshot."""

    def __init__(
        self,
        values: Mapping[str, Any],
        candidate_snapshot: Mapping[str, Mapping[str, Any]],
    ) -> None:
        super().__init__(values)
        self.candidate_snapshot = candidate_snapshot


def fail(code: str, detail: str | None = None) -> None:
    if detail:
        raise InventoryError(f"{code}:{detail}")
    raise InventoryError(code)


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON_DUPLICATE_KEY", key)
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    fail("JSON_NONFINITE", value)


def value_depth(value: Any, level: int = 0) -> int:
    if level > 64:
        fail("VALUE_DEPTH")
    if isinstance(value, dict):
        return max(
            (value_depth(item, level + 1) for item in value.values()), default=level
        )
    if isinstance(value, list):
        return max((value_depth(item, level + 1) for item in value), default=level)
    if isinstance(value, float) and not math.isfinite(value):
        fail("VALUE_NONFINITE")
    return level


def validate_unicode_scalars(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            fail("UNICODE_SURROGATE")
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_unicode_scalars(key)
            validate_unicode_scalars(item)
    elif isinstance(value, list):
        for item in value:
            validate_unicode_scalars(item)


def strict_json(payload: bytes, *, label: str, maximum: int = MAX_BLOB_BYTES) -> Any:
    if not payload or len(payload) > maximum:
        fail("JSON_SIZE", label)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=json_pairs,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InventoryError(f"JSON_INVALID:{label}") from error
    value_depth(value)
    validate_unicode_scalars(value)
    return value


def valid_path(path: str) -> bool:
    if (
        not isinstance(path, str)
        or not path
        or len(path.encode("utf-8")) > MAX_PATH_BYTES
    ):
        return False
    if (
        path != unicodedata.normalize("NFC", path)
        or "\\" in path
        or "\x00" in path
        or any(ord(character) < 32 for character in path)
    ):
        return False
    pure = PurePosixPath(path)
    return not pure.is_absolute() and all(
        part not in {"", ".", "..", ".git"} for part in pure.parts
    )


def command(
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout: int = 30,
    maximum: int = MAX_COMMAND_OUTPUT_BYTES,
    environment: Mapping[str, str] | None = None,
    allow_stderr: bool = False,
    input_payload: bytes | None = None,
    require_success: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    env = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    if environment:
        env.update(environment)
    input_file: io.BufferedRandom | None = None
    process: subprocess.Popen[bytes] | None = None
    stdout = bytearray()
    stderr = bytearray()
    try:
        if input_payload is not None:
            if len(input_payload) > MAX_AGGREGATE_BLOB_BYTES:
                fail("COMMAND_INPUT_LIMIT", arguments[0])
            input_file = tempfile.TemporaryFile()
            input_file.write(input_payload)
            input_file.seek(0)
        process = subprocess.Popen(
            list(arguments),
            cwd=cwd,
            env=env,
            stdin=input_file if input_file is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            fail("COMMAND_PIPE", arguments[0])
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, stdout)
            selector.register(process.stderr, selectors.EVENT_READ, stderr)
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                events = selector.select(min(remaining, 0.25))
                if not events and process.poll() is not None:
                    events = [
                        (key, selectors.EVENT_READ)
                        for key in tuple(selector.get_map().values())
                    ]
                for key, _mask in events:
                    chunk = os.read(key.fd, 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = key.data
                    target.extend(chunk)
                    if len(target) > maximum:
                        fail("COMMAND_OUTPUT_LIMIT", arguments[0])
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    except (OSError, subprocess.TimeoutExpired) as error:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        raise InventoryError(f"COMMAND_EXECUTION:{arguments[0]}") from error
    except BaseException:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        raise
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        if input_file is not None:
            input_file.close()
    completed = subprocess.CompletedProcess(
        list(arguments),
        returncode,
        bytes(stdout),
        bytes(stderr),
    )
    if require_success and completed.returncode != 0:
        fail("COMMAND_FAILED", f"{arguments[0]}:{completed.returncode}")
    if completed.stderr and not allow_stderr:
        fail("COMMAND_STDERR", arguments[0])
    return completed


def git_environment(repo: Path) -> dict[str, str]:
    return {
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": os.fspath(repo.resolve()),
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": "/dev/null",
        "GIT_CONFIG_KEY_2": "core.fsmonitor",
        "GIT_CONFIG_VALUE_2": "false",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def git(
    repo: Path,
    *arguments: str,
    maximum: int = MAX_COMMAND_OUTPUT_BYTES,
    allow_stderr: bool = False,
) -> bytes:
    return command(
        [
            GIT_EXECUTABLE,
            "--no-replace-objects",
            "--no-optional-locks",
            "-c",
            "core.pager=cat",
            "-c",
            "color.ui=false",
            *arguments,
        ],
        cwd=repo,
        timeout=30,
        maximum=maximum,
        environment=git_environment(repo),
        allow_stderr=allow_stderr,
    ).stdout


def resolve_commit(repo: Path, value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        fail("FREEZE_COMMIT_FORMAT")
    try:
        resolved = (
            git(repo, "rev-parse", "--verify", f"{value}^{{commit}}")
            .decode("ascii")
            .strip()
        )
    except UnicodeDecodeError as error:
        raise InventoryError("FREEZE_COMMIT_ENCODING") from error
    if resolved != value:
        fail("FREEZE_COMMIT_RESOLUTION")
    return resolved


def commit_file(
    repo: Path,
    commit: str,
    path: str,
    *,
    maximum: int = MAX_BLOB_BYTES,
) -> bytes:
    if not valid_path(path):
        fail("COMMIT_FILE_PATH", path)
    return git(repo, "cat-file", "blob", f"{commit}:{path}", maximum=maximum)


def implementation_parent(repo: Path, implementation_commit: str) -> str:
    line = (
        git(
            repo,
            "rev-list",
            "--parents",
            "-n",
            "1",
            implementation_commit,
        )
        .decode("ascii")
        .strip()
    )
    fields = line.split()
    if (
        len(fields) != 2
        or fields[0] != implementation_commit
        or re.fullmatch(r"[0-9a-f]{40}", fields[1]) is None
    ):
        fail("IMPLEMENTATION_PARENT")
    return fields[1]


def commit_meta(repo: Path, commit: str) -> dict[str, str]:
    try:
        fields = (
            git(
                repo,
                "show",
                "-s",
                "--format=%H%x00%P%x00%T%x00%s%x00%an%x00%ae",
                commit,
            )
            .decode("utf-8")
            .rstrip("\n")
            .split("\x00")
        )
    except UnicodeDecodeError as error:
        raise InventoryError("COMMIT_METADATA_ENCODING") from error
    if len(fields) != 6 or fields[0] != commit:
        fail("COMMIT_METADATA")
    return {
        "commit": fields[0],
        "parents": fields[1],
        "tree": fields[2],
        "subject": fields[3],
        "author_name": fields[4],
        "author_email": fields[5],
    }


def changed_statuses(repo: Path, parent: str, commit: str) -> dict[str, str]:
    raw = git(
        repo,
        "diff-tree",
        "--no-commit-id",
        "--name-status",
        "-r",
        "--no-renames",
        "-z",
        parent,
        commit,
    )
    fields = raw.split(b"\x00")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        fail("DIFF_FORMAT")
    result: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        try:
            status = fields[index].decode("ascii")
            path = fields[index + 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise InventoryError("DIFF_ENCODING") from error
        if status not in {"A", "M", "D"} or not valid_path(path) or path in result:
            fail("DIFF_STATUS")
        result[path] = status
    return dict(sorted(result.items()))


def verify_signed_commit(
    repo: Path,
    commit: str,
    allowed_signers_payload: bytes,
) -> dict[str, Any]:
    if not allowed_signers_payload or len(allowed_signers_payload) > 65_536:
        fail("ALLOWED_SIGNERS")
    with tempfile.TemporaryDirectory(prefix="haldir-ch-t003-signers-") as directory:
        allowed = Path(directory) / "allowed-signers"
        allowed.write_bytes(allowed_signers_payload)
        completed = command(
            [
                GIT_EXECUTABLE,
                "--no-replace-objects",
                "--no-optional-locks",
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={allowed}",
                "-c",
                f"gpg.ssh.program={SSH_KEYGEN_EXECUTABLE}",
                "-c",
                "gpg.ssh.revocationFile=/dev/null",
                "-c",
                "gpg.minTrustLevel=fully",
                "verify-commit",
                commit,
            ],
            cwd=repo,
            timeout=15,
            environment=git_environment(repo),
            allow_stderr=True,
        )
    transcript = completed.stdout + completed.stderr
    return {
        "verified": True,
        "allowed_signers_sha256": sha256(allowed_signers_payload),
        "verification_transcript_sha256": sha256(transcript),
    }


def validate_freeze_trust_anchor(repo: Path, freeze_commit: str) -> dict[str, Any]:
    meta = commit_meta(repo, freeze_commit)
    if (
        meta["parents"] != PRIOR_LIFECYCLE["activation_commit"]
        or meta["subject"] != EXPECTED_FREEZE_SUBJECT
        or meta["author_name"] != AUTHOR["name"]
        or meta["author_email"] != AUTHOR["email"]
    ):
        fail("FREEZE_TRUST_ANCHOR")
    if (
        changed_statuses(
            repo,
            PRIOR_LIFECYCLE["activation_commit"],
            freeze_commit,
        )
        != FREEZE_PLAN
    ):
        fail("FREEZE_TRUST_DIFF")
    allowed_signers = commit_file(
        repo,
        PRIOR_LIFECYCLE["activation_commit"],
        ALLOWED_SIGNERS_PATH,
        maximum=65_536,
    )
    if (
        commit_file(repo, freeze_commit, ALLOWED_SIGNERS_PATH, maximum=65_536)
        != allowed_signers
    ):
        fail("ALLOWED_SIGNERS_DRIFT")
    return verify_signed_commit(repo, freeze_commit, allowed_signers)


def registered_product_verifier(
    repo: Path,
    freeze_commit: str,
) -> tuple[Callable[[Path, str, str], None], dict[str, Any]]:
    registry_payload = commit_file(
        repo,
        freeze_commit,
        VERIFIER_REGISTRY_PATH,
    )
    registry = strict_json(
        registry_payload,
        label="frozen-verifier-registry",
        maximum=MAX_BLOB_BYTES,
    )
    if not isinstance(registry, dict) or not isinstance(
        registry.get("registrations"), list
    ):
        fail("FROZEN_VERIFIER_REGISTRY_SHAPE")
    matches = [
        item
        for item in registry["registrations"]
        if isinstance(item, dict)
        and item.get("task_id") == TASK_ID
        and item.get("epoch") == EPOCH
    ]
    if len(matches) != 1:
        fail("FROZEN_VERIFIER_REGISTRATION_COUNT", str(len(matches)))
    verifier = matches[0].get("verifier")
    if not isinstance(verifier, dict):
        fail("FROZEN_VERIFIER_REGISTRATION_SHAPE")
    path = verifier.get("path")
    expected_sha256 = verifier.get("sha256")
    expected_bytes = verifier.get("bytes")
    expected_lines = verifier.get("lines")
    if (
        path != FROZEN_VERIFIER_PATH
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "") is None
        or type(expected_bytes) is not int
        or type(expected_lines) is not int
    ):
        fail("FROZEN_VERIFIER_IDENTITY")
    payload = commit_file(repo, freeze_commit, path)
    if (
        sha256(payload) != expected_sha256
        or len(payload) != expected_bytes
        or len(payload.splitlines()) != expected_lines
    ):
        fail("FROZEN_VERIFIER_BINDING")
    module = types.ModuleType("_haldir_ch_t003_frozen_product_verifier")
    module.__file__ = f"{freeze_commit}:{path}"
    try:
        exec(compile(payload, module.__file__, "exec"), module.__dict__)
    except Exception as error:
        raise InventoryError("FROZEN_VERIFIER_LOAD") from error
    validate_implementation = getattr(module, "validate_implementation", None)
    if (
        getattr(module, "TASK_ID", None) != TASK_ID
        or getattr(module, "EPOCH", None) != EPOCH
        or not callable(validate_implementation)
    ):
        fail("FROZEN_VERIFIER_INTERFACE")
    public_record = {
        "path": path,
        "sha256": expected_sha256,
        "bytes": expected_bytes,
        "lines": expected_lines,
        "registry_path": VERIFIER_REGISTRY_PATH,
        "registry_sha256": sha256(registry_payload),
        "entrypoint": "validate_implementation",
    }
    return validate_implementation, public_record


def verify_products(repo: Path, implementation_commit: str) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    implementation_commit = resolve_commit(repo, implementation_commit)
    freeze_commit = implementation_parent(repo, implementation_commit)
    validate_freeze_trust_anchor(repo, freeze_commit)
    validate_implementation, verifier = registered_product_verifier(repo, freeze_commit)
    try:
        validate_implementation(repo, freeze_commit, implementation_commit)
    except Exception as error:
        raise InventoryError(f"FROZEN_PRODUCT_VERIFIER:{error}") from error
    products = []
    for path in OUTPUT_PATHS:
        payload = commit_file(
            repo,
            implementation_commit,
            path,
            maximum=MAX_OUTPUT_BYTES,
        )
        products.append(
            {
                "path": path,
                "bytes": len(payload),
                "sha256": sha256(payload),
            }
        )
    return {
        "schema_version": "1.0.0",
        "schema_id": "haldir.ch-t003.product-verification.v1",
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "mode": "FROZEN_PRODUCT_CHECKS",
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "verifier": verifier,
        "products": products,
        "network_used": False,
        "repository_mutated": False,
        "result": "PASS",
    }


def tree_snapshot(
    repo: Path, commit: str
) -> tuple[str, str, list[dict[str, Any]], dict[str, bytes]]:
    object_format = (
        git(repo, "rev-parse", "--show-object-format").decode("ascii").strip()
    )
    if object_format != "sha1":
        fail("OBJECT_FORMAT", object_format)
    tree = git(repo, "show", "-s", "--format=%T", commit).decode("ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40}", tree) is None:
        fail("TREE_ID")
    raw = git(repo, "ls-tree", "-r", "-z", "--full-tree", "-l", commit)
    entries: list[dict[str, Any]] = []
    aggregate = 0
    seen: set[str] = set()
    for item in raw.split(b"\x00"):
        if not item:
            continue
        try:
            header, raw_path = item.split(b"\t", 1)
            mode, object_type, object_id, raw_size = header.decode("ascii").split()
            path = raw_path.decode("utf-8")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as error:
            raise InventoryError("TREE_RECORD") from error
        if not valid_path(path) or path in seen:
            fail("TREE_PATH", path)
        seen.add(path)
        if mode not in REGULAR_MODES or object_type != "blob":
            fail("TREE_NONREGULAR", path)
        if size < 0 or size > MAX_BLOB_BYTES:
            fail("BLOB_SIZE", path)
        aggregate += size
        if aggregate > MAX_AGGREGATE_BLOB_BYTES:
            fail("TREE_AGGREGATE_SIZE")
        entries.append(
            {
                "path": path,
                "git_mode": mode,
                "git_object_type": object_type,
                "git_object_id": object_id,
                "bytes": size,
            }
        )
    if (
        not entries
        or len(entries) > MAX_TREE_ENTRIES
        or entries != sorted(entries, key=lambda item: item["path"])
    ):
        fail("TREE_CARDINALITY_OR_ORDER")
    batch_input = b"".join(
        (item["git_object_id"] + "\n").encode("ascii") for item in entries
    )
    process = command(
        [
            GIT_EXECUTABLE,
            "--no-replace-objects",
            "--no-optional-locks",
            "cat-file",
            "--batch",
        ],
        cwd=repo,
        timeout=30,
        maximum=MAX_AGGREGATE_BLOB_BYTES + len(entries) * 128,
        environment=git_environment(repo),
        input_payload=batch_input,
    )
    offset = 0
    blobs: dict[str, bytes] = {}
    for entry in entries:
        newline = process.stdout.find(b"\n", offset)
        if newline < 0:
            fail("CAT_FILE_HEADER")
        fields = process.stdout[offset:newline].split()
        if (
            len(fields) != 3
            or fields[0].decode("ascii") != entry["git_object_id"]
            or fields[1] != b"blob"
        ):
            fail("CAT_FILE_HEADER")
        try:
            size = int(fields[2])
        except ValueError as error:
            raise InventoryError("CAT_FILE_SIZE") from error
        start = newline + 1
        end = start + size
        if (
            size != entry["bytes"]
            or end >= len(process.stdout)
            or process.stdout[end : end + 1] != b"\n"
        ):
            fail("CAT_FILE_PAYLOAD", entry["path"])
        payload = process.stdout[start:end]
        if payload.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            fail("LFS_POINTER", entry["path"])
        blobs[entry["path"]] = payload
        offset = end + 1
    if offset != len(process.stdout) or len(blobs) != len(entries):
        fail("CAT_FILE_TRAILING")
    return object_format, tree, entries, blobs


def content_kind(path: str, payload: bytes) -> str:
    if path.casefold().endswith(
        (".gz", ".ico", ".jpeg", ".jpg", ".pdf", ".png", ".wasm", ".zip")
    ):
        return "BINARY"
    if b"\x00" in payload:
        return "BINARY"
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return "BINARY"
    return "UTF8"


def classify_path(path: str) -> tuple[str, str, str]:
    lowered = path.casefold()
    name = PurePosixPath(path).name.casefold()
    suffix = PurePosixPath(path).suffix.casefold()
    if suffix not in KNOWN_SUFFIXES and name not in {
        "dockerfile",
        "justfile",
        "authors",
        "copying",
        "notice",
    }:
        fail("UNKNOWN_EXTENSION", path)
    if (
        suffix in {".md", ".rst", ".txt"}
        or name.startswith(("readme", "license"))
        or name in {"authors", "copying", "notice"}
        or lowered.startswith("assets/")
    ):
        return "PUBLIC_DOCUMENTATION", "SURFACE", "HUMAN_OR_BRAND_DOCUMENTATION"
    if (
        lowered.startswith(
            ("contracts/", "crates/", "ffi/", "include/", "schemas/", "formal/")
        )
        or lowered.startswith("tools/haldir-ctl/")
        or suffix in {".proto", ".tla"}
    ):
        return "PUBLIC_API_OR_SCHEMA", "SURFACE", "CODE_SCHEMA_OR_FORMAL_INTERFACE"
    if lowered.startswith(
        (".github/", "config/", "configs/", "deploy/", "profiles/")
    ) or name in {
        ".gitignore",
        ".ncp-consumer",
        "cargo.lock",
        "cargo.toml",
        "deny.toml",
        "dockerfile",
        "dockerfile.dockerignore",
        "justfile",
        "pins.toml",
        "rust-toolchain.toml",
    }:
        return "BUILD_OR_DEPLOYMENT", "SURFACE", "BUILD_AUTOMATION_OR_DEPLOYMENT_INPUT"
    if lowered.startswith(("release/", "audit/", "evidence/")):
        return (
            "EXCLUDED_INTERNAL_EVIDENCE_OR_RELEASE",
            "EXCLUDED",
            "RETAINED_ASSURANCE_OR_RELEASE_RECORD_NOT_RUNTIME_INTERFACE",
        )
    if (
        lowered.startswith("tools/")
        or "/tests/" in f"/{lowered}"
        or name.startswith("test_")
    ):
        return (
            "EXCLUDED_INTERNAL_TEST_OR_TOOL",
            "EXCLUDED",
            "INTERNAL_TEST_OR_ASSURANCE_TOOL_NOT_RUNTIME_INTERFACE",
        )
    if lowered.startswith("assets/") or suffix in {".ico", ".png", ".svg"}:
        return "EXCLUDED_NONINTERFACE_ASSET", "EXCLUDED", "NONINTERFACE_ASSET"
    fail("UNCLASSIFIED_PATH", path)


def claim_ids(payload: bytes) -> list[str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return sorted(set(CLAIM_ID_PATTERN.findall(text)))


def line_count(payload: bytes) -> int | None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return len(text.splitlines())


def surface_types(path: str, payload: bytes, classification: str) -> list[str]:
    lowered = path.casefold()
    name = PurePosixPath(path).name.casefold()
    result: set[str] = set()
    if classification == "PUBLIC_DOCUMENTATION":
        result.add("DOCUMENTATION")
    if lowered.startswith("crates/") and lowered.endswith(".rs"):
        result.add("RUST_API_SOURCE")
        text = payload.decode("utf-8")
        if (
            re.search(r"(?m)^\s*(?:#\[[^\n]+\]\s*)*pub\s+", text)
            or "#[macro_export]" in text
        ):
            result.add("RUST_PUBLIC_DECLARATION_SOURCE")
    if name == "cargo.toml":
        result.add("PACKAGE_MANIFEST")
    if lowered.startswith(".github/workflows/"):
        result.add("AUTOMATION_WORKFLOW")
    if lowered.startswith("deploy/"):
        result.add("DEPLOYMENT_CONFIGURATION")
    if lowered.startswith("contracts/") or name.endswith((".proto", ".schema.json")):
        result.add("SCHEMA_OR_CONTRACT")
    if lowered.startswith("formal/"):
        result.add("FORMAL_MODEL_OR_CONFIGURATION")
    if (
        lowered.startswith("tools/haldir-ctl/")
        or "/src/bin/" in f"/{lowered}"
        or "/examples/" in f"/{lowered}"
        or name == "main.rs"
    ):
        result.add("COMMAND_LINE_INTERFACE_SOURCE")
    folded = payload.decode("utf-8", errors="ignore").casefold()
    if any(
        marker in folded
        for marker in ("zenoh", "keyexpr", "interprocess", "ipc", "route")
    ):
        result.add("IPC_OR_ROUTE_SOURCE")
    if lowered.startswith("release/"):
        result.add("RELEASE_RECORD")
    if not result:
        result.add("CLASSIFIED_FILE")
    return sorted(result)


def validate_toml_and_yaml(path: str, payload: bytes) -> None:
    lowered = path.casefold()
    if lowered.endswith(".toml"):
        try:
            tomllib.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise InventoryError(f"TOML_INVALID:{path}") from error
    if lowered.endswith((".yaml", ".yml")):
        validate_yaml_duplicate_keys(payload, path)
    if lowered.endswith(".json5"):
        strict_json(payload, label=path)


def yaml_value_without_comment(value: str, path: str, number: int) -> str:
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    result: list[str] = []
    pairs = {"]": "[", "}": "{"}
    index = 0
    while index < len(value):
        character = value[index]
        if quote == '"':
            result.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if quote == "'":
            result.append(character)
            if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                result.append(value[index + 1])
                index += 2
                continue
            if character == "'":
                quote = None
            index += 1
            continue
        if character in {'"', "'"}:
            quote = character
            result.append(character)
        elif character == "#" and (index == 0 or value[index - 1].isspace()):
            break
        elif character in "[{":
            stack.append(character)
            result.append(character)
        elif character in "]}":
            if not stack or stack.pop() != pairs[character]:
                fail("YAML_DELIMITER", f"{path}:{number}")
            result.append(character)
        else:
            result.append(character)
        index += 1
    if quote is not None or escaped or stack:
        fail("YAML_DELIMITER", f"{path}:{number}")
    return "".join(result).rstrip()


def validate_yaml_value(value: str, path: str, number: int) -> str:
    value = yaml_value_without_comment(value, path, number)
    if not value:
        return "EMPTY"
    if re.fullmatch(r"[|>](?:[+-]|[1-9]|[+-][1-9]|[1-9][+-])?", value):
        return "BLOCK"
    if value[0] in "[{":
        normalized = re.sub(
            r"([,{]\s*)([A-Za-z0-9_.${}/-]+)\s*:",
            r'\1"\2":',
            value,
        )
        try:
            strict_json(
                normalized.encode("utf-8"),
                label=f"{path}:{number}:flow",
                maximum=MAX_BLOB_BYTES,
            )
        except InventoryError as error:
            raise InventoryError(f"YAML_FLOW_INVALID:{path}:{number}") from error
    elif value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as error:
            raise InventoryError(f"YAML_QUOTED_SCALAR:{path}:{number}") from error
        if not isinstance(parsed, str):
            fail("YAML_QUOTED_SCALAR", f"{path}:{number}")
        validate_unicode_scalars(parsed)
    elif value.startswith("'"):
        if (
            len(value) < 2
            or not value.endswith("'")
            or re.search(r"(?<!')'(?!')", value[1:-1])
        ):
            fail("YAML_QUOTED_SCALAR", f"{path}:{number}")
    elif (
        value.startswith(("*", "&", "!", "---", "..."))
        or re.search(r"(?:^|\s)[&*!][^\s]+", value)
        or re.search(r":(?:\s|$)", value)
    ):
        fail("YAML_UNSUPPORTED_SCALAR", f"{path}:{number}")
    return "SCALAR"


YAML_KEY_PATTERN = re.compile(
    r"""(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[A-Za-z0-9_.${}/-]+)"""
    r"""\s*:(?=\s|$)"""
)


def yaml_mapping_entry(text: str, path: str, number: int) -> tuple[str, str] | None:
    match = YAML_KEY_PATTERN.match(text)
    if match is None:
        return None
    token = match.group("key")
    if token.startswith('"'):
        try:
            key = json.loads(token)
        except json.JSONDecodeError as error:
            raise InventoryError(f"YAML_KEY:{path}:{number}") from error
        validate_unicode_scalars(key)
    elif token.startswith("'"):
        key = token[1:-1].replace("''", "'")
    else:
        key = token
    if not isinstance(key, str) or not key or key == "<<":
        fail("YAML_KEY", f"{path}:{number}")
    return key, text[match.end() :].lstrip()


def validate_yaml_duplicate_keys(payload: bytes, path: str) -> None:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise InventoryError(f"YAML_UTF8:{path}") from error
    scopes: list[tuple[int, str, set[str]]] = []
    block_scalar_indent: int | None = None
    pending_child_indent: int | None = None
    for number, raw_line in enumerate(lines, start=1):
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if block_scalar_indent is not None:
            if not raw_line.strip() or indent > block_scalar_indent:
                continue
            block_scalar_indent = None
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip())]:
            fail("YAML_TAB_INDENT", f"{path}:{number}")
        if indent % 2:
            fail("YAML_INDENT", f"{path}:{number}")
        text = raw_line.strip()
        while scopes and scopes[-1][0] > indent:
            scopes.pop()
        if pending_child_indent is not None:
            if indent > pending_child_indent:
                if indent != pending_child_indent + 2:
                    fail("YAML_INDENT", f"{path}:{number}")
                kind = "SEQUENCE" if text == "-" or text.startswith("- ") else "MAPPING"
                scopes.append((indent, kind, set()))
            pending_child_indent = None
        if not scopes:
            if indent != 0:
                fail("YAML_INDENT", f"{path}:{number}")
            kind = "SEQUENCE" if text == "-" or text.startswith("- ") else "MAPPING"
            scopes.append((0, kind, set()))
        if scopes[-1][0] != indent:
            fail("YAML_INDENT", f"{path}:{number}")
        kind = scopes[-1][1]
        if kind == "SEQUENCE":
            if text == "-":
                pending_child_indent = indent
                continue
            if not text.startswith("- "):
                fail("YAML_SEQUENCE", f"{path}:{number}")
            item = text[2:].lstrip()
            entry = yaml_mapping_entry(item, path, number)
            if entry is None:
                if validate_yaml_value(item, path, number) != "SCALAR":
                    fail("YAML_SEQUENCE_VALUE", f"{path}:{number}")
                continue
            key, value = entry
            item_scope: set[str] = {key}
            scopes.append((indent + 2, "MAPPING", item_scope))
            status = validate_yaml_value(value, path, number)
            if status == "EMPTY":
                pending_child_indent = indent + 2
            elif status == "BLOCK":
                block_scalar_indent = indent + 2
            continue
        if text == "-" or text.startswith("- "):
            fail("YAML_MAPPING", f"{path}:{number}")
        entry = yaml_mapping_entry(text, path, number)
        if entry is None:
            fail("YAML_SYNTAX", f"{path}:{number}")
        key, value = entry
        scope = scopes[-1][2]
        if key in scope:
            fail("YAML_DUPLICATE_KEY", f"{path}:{number}:{key}")
        scope.add(key)
        status = validate_yaml_value(value, path, number)
        if status == "EMPTY":
            pending_child_indent = indent
        elif status == "BLOCK":
            block_scalar_indent = indent


def inventory_records(
    entries: Sequence[dict[str, Any]], blobs: Mapping[str, bytes]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for entry in entries:
        path = entry["path"]
        payload = blobs[path]
        classification, disposition, reason = classify_path(path)
        validate_toml_and_yaml(path, payload)
        if path.casefold().endswith((".json", ".json5")):
            strict_json(payload, label=path)
        records.append(
            {
                **entry,
                "sha256": sha256(payload),
                "lines": line_count(payload),
                "content_kind": content_kind(path, payload),
                "classification": classification,
                "disposition": disposition,
                "classification_reason": reason,
                "surface_types": surface_types(path, payload, classification),
                "claim_ids": claim_ids(payload),
            }
        )
    if len(records) != len(entries) or {item["path"] for item in records} != {
        item["path"] for item in entries
    }:
        fail("INVENTORY_PARTITION")
    return records


def archive_member_path(value: str) -> str:
    if not valid_path(value):
        fail("ARCHIVE_MEMBER_PATH", repr(value))
    return value


def looks_like_archive(payload: bytes) -> bool:
    return any(payload.startswith(prefix) for prefix in ARCHIVE_MAGIC_PREFIXES) or (
        len(payload) >= 262 and payload[257:262] == b"ustar"
    )


def zip_member_envelopes(
    path: str,
    payload: bytes,
    archive: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
) -> dict[int, tuple[int, int]]:
    ordered_offsets = sorted(info.header_offset for info in infos)
    eocd_offset = payload.rfind(b"PK\x05\x06")
    if eocd_offset < 0 or eocd_offset + 22 > len(payload):
        fail("ZIP_EOCD", path)
    eocd = payload[eocd_offset : eocd_offset + 22]
    comment_length = int.from_bytes(eocd[20:22], "little")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if (
        len(set(ordered_offsets)) != len(ordered_offsets)
        or ordered_offsets[0] != 0
        or int.from_bytes(eocd[4:6], "little") != 0
        or int.from_bytes(eocd[6:8], "little") != 0
        or int.from_bytes(eocd[8:10], "little") != len(infos)
        or int.from_bytes(eocd[10:12], "little") != len(infos)
        or central_offset != archive.start_dir
        or central_offset + central_size != eocd_offset
        or comment_length != 0
        or archive.comment != b""
        or eocd_offset + 22 + comment_length != len(payload)
    ):
        fail("ZIP_ENVELOPE", path)
    offset_indexes = {
        header_offset: index for index, header_offset in enumerate(ordered_offsets)
    }
    bounds: dict[int, tuple[int, int]] = {}
    for info in infos:
        index = offset_indexes[info.header_offset]
        next_boundary = (
            ordered_offsets[index + 1]
            if index + 1 < len(ordered_offsets)
            else archive.start_dir
        )
        local_header = payload[info.header_offset : info.header_offset + 30]
        if len(local_header) != 30 or local_header[:4] != b"PK\x03\x04":
            fail("ZIP_LOCAL_HEADER", f"{path}:{info.filename}")
        name_length = int.from_bytes(local_header[26:28], "little")
        extra_length = int.from_bytes(local_header[28:30], "little")
        local_name_start = info.header_offset + 30
        local_name_end = local_name_start + name_length
        local_extra_end = local_name_end + extra_length
        data_start = local_extra_end
        data_end = data_start + info.compress_size
        local_name = payload[local_name_start:local_name_end]
        local_extra = payload[local_name_end:local_extra_end]
        try:
            expected_name = info.orig_filename.encode(
                "utf-8" if info.flag_bits & 0x800 else "cp437"
            )
        except UnicodeEncodeError:
            fail("ZIP_MEMBER_ENCODING", f"{path}:{info.filename}")
        year, month, day, hour, minute, second = info.date_time
        expected_time = (hour << 11) | (minute << 5) | (second // 2)
        expected_date = ((year - 1980) << 9) | (month << 5) | day
        local_crc = int.from_bytes(local_header[14:18], "little")
        local_compressed = int.from_bytes(local_header[18:22], "little")
        local_expanded = int.from_bytes(local_header[22:26], "little")
        if info.flag_bits & 0x08:
            descriptor = payload[data_end : data_end + 16]
            envelope_end = data_end + 16
            descriptor_valid = (
                len(descriptor) == 16
                and descriptor[:4] == b"PK\x07\x08"
                and int.from_bytes(descriptor[4:8], "little") == info.CRC
                and int.from_bytes(descriptor[8:12], "little") == info.compress_size
                and int.from_bytes(descriptor[12:16], "little") == info.file_size
                and local_crc == 0
                and local_compressed == 0
                and local_expanded == 0
            )
        else:
            envelope_end = data_end
            descriptor_valid = (
                local_crc == info.CRC
                and local_compressed == info.compress_size
                and local_expanded == info.file_size
            )
        if (
            int.from_bytes(local_header[4:6], "little") != info.extract_version
            or int.from_bytes(local_header[6:8], "little") != info.flag_bits
            or int.from_bytes(local_header[8:10], "little") != info.compress_type
            or int.from_bytes(local_header[10:12], "little") != expected_time
            or int.from_bytes(local_header[12:14], "little") != expected_date
            or local_name != expected_name
            or local_extra != info.extra
            or data_start < local_name_start
            or data_end < data_start
            or not descriptor_valid
            or envelope_end != next_boundary
            or next_boundary > archive.start_dir
        ):
            fail("ZIP_ENVELOPE", f"{path}:{info.filename}")
        bounds[info.header_offset] = (data_start, data_end)
    return bounds


def zip_members(
    path: str, payload: bytes
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    members: list[dict[str, Any]] = []
    contents: dict[str, bytes] = {}
    expanded = 0
    seen: set[str] = set()
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (zipfile.BadZipFile, OSError) as error:
        raise InventoryError(f"ZIP_INVALID:{path}") from error
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
            fail("ZIP_MEMBER_COUNT", path)
        envelopes = zip_member_envelopes(path, payload, archive, infos)
        for info in infos:
            name = archive_member_path(info.filename)
            if name in seen:
                fail("ZIP_DUPLICATE_MEMBER", f"{path}:{name}")
            seen.add(name)
            if info.flag_bits & ~(0x800 | 0x08):
                fail("ZIP_FLAGS", f"{path}:{name}")
            if info.compress_type not in {
                zipfile.ZIP_STORED,
                zipfile.ZIP_DEFLATED,
            }:
                fail("ZIP_COMPRESSION", f"{path}:{name}")
            if (
                info.is_dir()
                or info.comment != b""
                or info.extra != b""
                or name.casefold().endswith(NESTED_ARCHIVE_SUFFIXES)
            ):
                fail("ZIP_MEMBER_POLICY", f"{path}:{name}")
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if file_type not in {0, stat.S_IFREG}:
                fail("ZIP_NONREGULAR", f"{path}:{name}")
            if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                fail("ARCHIVE_MEMBER_SIZE", f"{path}:{name}")
            expanded += info.file_size
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                fail("ARCHIVE_EXPANDED_SIZE", path)
            if info.file_size > MAX_COMPRESSION_RATIO * max(1, info.compress_size):
                fail("ZIP_RATIO", f"{path}:{name}")
            data_start, data_end = envelopes[info.header_offset]
            compressed = payload[data_start:data_end]
            if info.compress_type == zipfile.ZIP_STORED:
                data = compressed
            else:
                decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                try:
                    data = decompressor.decompress(
                        compressed,
                        MAX_ARCHIVE_MEMBER_BYTES + 1,
                    )
                except zlib.error as error:
                    raise InventoryError(f"ZIP_MEMBER_READ:{path}:{name}") from error
                if (
                    not decompressor.eof
                    or decompressor.unused_data
                    or decompressor.unconsumed_tail
                ):
                    fail("ZIP_DEFLATE_BOUNDARY", f"{path}:{name}")
            if (
                len(data) != info.file_size
                or (zlib.crc32(data) & 0xFFFFFFFF) != info.CRC
            ):
                fail("ZIP_CRC_OR_SIZE", f"{path}:{name}")
            if looks_like_archive(data):
                fail("ZIP_NESTED_ARCHIVE", f"{path}:{name}")
            contents[name] = data
            members.append(
                {
                    "name": name,
                    "bytes": len(data),
                    "compressed_bytes": info.compress_size,
                    "crc32": info.CRC,
                    "sha256": sha256(data),
                    "content_kind": content_kind(name, data),
                    "claim_ids": claim_ids(data),
                }
            )
    return sorted(members, key=lambda item: item["name"]), contents


def gzip_members(
    path: str, payload: bytes
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    members: list[dict[str, Any]] = []
    contents: dict[str, bytes] = {}
    remaining = payload
    expanded = 0
    index = 0
    while remaining:
        index += 1
        if index > MAX_ARCHIVE_MEMBERS:
            fail("GZIP_MEMBER_COUNT", path)
        if len(remaining) < 10 or remaining[:3] != b"\x1f\x8b\x08" or remaining[3] != 0:
            fail("GZIP_HEADER", f"{path}:{index}")
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            data = decompressor.decompress(remaining, MAX_ARCHIVE_MEMBER_BYTES + 1)
        except zlib.error as error:
            raise InventoryError(f"GZIP_INVALID:{path}:{index}") from error
        if (
            not decompressor.eof
            or decompressor.unconsumed_tail
            or len(data) > MAX_ARCHIVE_MEMBER_BYTES
        ):
            fail("GZIP_TRUNCATED_OR_OVERSIZE", f"{path}:{index}")
        if looks_like_archive(data):
            fail("GZIP_NESTED_ARCHIVE", f"{path}:{index}")
        consumed = len(remaining) - len(decompressor.unused_data)
        if consumed <= 0:
            fail("GZIP_PROGRESS", path)
        if len(data) > MAX_COMPRESSION_RATIO * max(1, consumed):
            fail("GZIP_RATIO", f"{path}:{index}")
        expanded += len(data)
        if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            fail("ARCHIVE_EXPANDED_SIZE", path)
        natural_name = PurePosixPath(path).name.removesuffix(".gz")
        name = natural_name if index == 1 else f"{natural_name}#member-{index:04d}"
        contents[name] = data
        members.append(
            {
                "name": name,
                "bytes": len(data),
                "compressed_bytes": consumed,
                "crc32": None,
                "sha256": sha256(data),
                "content_kind": content_kind(name, data),
                "claim_ids": claim_ids(data),
            }
        )
        remaining = decompressor.unused_data
        if remaining:
            fail("GZIP_CONCATENATED", path)
    if not members:
        fail("GZIP_EMPTY", path)
    if len(members) != 1:
        fail("GZIP_MEMBER_COUNT", path)
    return members, contents


def inventory_archives(
    records: Sequence[dict[str, Any]], blobs: Mapping[str, bytes]
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], bytes]]:
    archives: list[dict[str, Any]] = []
    expanded_contents: dict[tuple[str, str], bytes] = {}
    aggregate = 0
    for record in records:
        path = record["path"]
        if path.casefold().endswith(".zip"):
            archive_type = "ZIP"
            members, contents = zip_members(path, blobs[path])
        elif path.casefold().endswith(".gz"):
            archive_type = "GZIP"
            members, contents = gzip_members(path, blobs[path])
        else:
            continue
        aggregate += sum(item["bytes"] for item in members)
        if aggregate > MAX_ARCHIVE_EXPANDED_BYTES:
            fail("ALL_ARCHIVES_EXPANDED_SIZE")
        for name, data in contents.items():
            expanded_contents[(path, name)] = data
        archives.append(
            {
                "path": path,
                "archive_type": archive_type,
                "source_sha256": record["sha256"],
                "source_bytes": record["bytes"],
                "members": members,
                "member_count": len(members),
                "expanded_bytes": sum(item["bytes"] for item in members),
                "members_sha256": sha256(canonical_json(members)),
            }
        )
    return archives, expanded_contents


def materialize_snapshot(
    root: Path, entries: Sequence[dict[str, Any]], blobs: Mapping[str, bytes]
) -> None:
    for entry in entries:
        path = root.joinpath(*PurePosixPath(entry["path"]).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blobs[entry["path"]])
        path.chmod(0o755 if entry["git_mode"] == "100755" else 0o644)


def tool_version(
    arguments: Sequence[str], *, cwd: Path, expected_prefix: str
) -> tuple[str, str]:
    completed = command(arguments, cwd=cwd, allow_stderr=False)
    try:
        version = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise InventoryError(f"TOOL_VERSION_ENCODING:{arguments[0]}") from error
    if not version.startswith(expected_prefix):
        fail("TOOL_VERSION", f"{arguments[0]}:{version}")
    return version, sha256(completed.stdout)


def bounded_path_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            fail(f"{label}_TYPE_OR_SIZE")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum:
                fail(f"{label}_SIZE")
        after = os.fstat(descriptor)
    except OSError as error:
        raise InventoryError(f"{label}_READ") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        observed != before.st_size
        or before.st_mode != after.st_mode
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        fail(f"{label}_CHANGED")
    return b"".join(chunks)


def rust_toolchain(repo: Path) -> dict[str, Any]:
    rustup = shutil.which("rustup")
    public_api = shutil.which("cargo-public-api")
    zig = shutil.which("zig")
    if rustup is None or public_api is None or zig is None:
        fail("RUST_ORACLE_TOOL_MISSING")
    sysroot_completed = command(
        [rustup, "run", PINNED_RUST_VERSION, "rustc", "--print", "sysroot"],
        cwd=repo,
    )
    try:
        sysroot = Path(sysroot_completed.stdout.decode("utf-8").strip()).resolve(
            strict=True
        )
    except (UnicodeDecodeError, OSError) as error:
        raise InventoryError("RUST_SYSROOT") from error
    tools: dict[str, dict[str, Any]] = {}
    for name in ("cargo", "rustc", "rustdoc"):
        try:
            path = (sysroot / "bin" / name).resolve(strict=True)
        except OSError:
            fail("RUST_TOOL_MISSING", name)
        completed = command([str(path), "--version", "--verbose"], cwd=repo)
        text = completed.stdout.decode("utf-8")
        if f" {PINNED_RUST_VERSION} " not in f" {text.splitlines()[0]} ":
            fail("RUST_TOOL_VERSION", name)
        tools[name] = {
            "path_role": f"rustup:{PINNED_RUST_VERSION}/bin/{name}",
            "version_output": text.splitlines(),
            "binary_sha256": sha256(
                bounded_path_bytes(
                    path,
                    maximum=MAX_TOOL_BINARY_BYTES,
                    label="RUST_TOOL_BINARY",
                )
            ),
        }
    public_api_path = Path(public_api).resolve(strict=True)
    completed = command([str(public_api_path), "--version"], cwd=repo)
    public_api_version = completed.stdout.decode("utf-8").strip()
    if public_api_version != f"cargo-public-api {PINNED_CARGO_PUBLIC_API_VERSION}":
        fail("CARGO_PUBLIC_API_VERSION", public_api_version)
    public_api_sha256 = sha256(
        bounded_path_bytes(
            public_api_path,
            maximum=MAX_TOOL_BINARY_BYTES,
            label="CARGO_PUBLIC_API_BINARY",
        )
    )
    expected_public_api_sha256 = (
        "acdc7b1733d52476fc2ce456a2a0292b82c367566fe0d2ab15c12b99974c8d24"
    )
    if public_api_sha256 != expected_public_api_sha256:
        fail("CARGO_PUBLIC_API_BINARY_SHA256", public_api_sha256)
    zig_path = Path(zig).resolve(strict=True)
    zig_completed = command([str(zig_path), "version"], cwd=repo)
    zig_version = zig_completed.stdout.decode("utf-8").strip()
    zig_sha256 = sha256(
        bounded_path_bytes(
            zig_path,
            maximum=MAX_TOOL_BINARY_BYTES,
            label="ZIG_BINARY",
        )
    )
    if zig_version != PINNED_ZIG_VERSION or zig_sha256 != PINNED_ZIG_SHA256:
        fail("ZIG_TOOL_IDENTITY", f"{zig_version}:{zig_sha256}")
    targets = (
        command(
            [
                rustup,
                "target",
                "list",
                "--installed",
                "--toolchain",
                PINNED_RUST_VERSION,
            ],
            cwd=repo,
        )
        .stdout.decode("utf-8")
        .splitlines()
    )
    if not set(RUST_TARGETS).issubset(targets):
        fail("RUST_TARGET_MISSING")
    return {
        "toolchain": PINNED_RUST_VERSION,
        "rustup_path": rustup,
        "sysroot": str(sysroot),
        "tools": tools,
        "cargo_public_api": {
            "version": public_api_version,
            "binary_sha256": public_api_sha256,
            "expected_binary_sha256_on_capture_host": expected_public_api_sha256,
            "path": str(public_api_path),
        },
        "cross_compiler": {
            "role": "LINUX_TARGET_C_BUILD_SCRIPTS_ONLY",
            "version": zig_version,
            "binary_sha256": zig_sha256,
            "expected_binary_sha256_on_capture_host": PINNED_ZIG_SHA256,
            "path": str(zig_path),
            "target": "x86_64-linux-gnu",
            "cc_environment": (
                "CC_x86_64_unknown_linux_gnu=<zig-path> cc -target x86_64-linux-gnu"
            ),
            "ar_environment": "AR_x86_64_unknown_linux_gnu=<zig-path> ar",
            "cc_defaults_disabled": True,
        },
        "targets": list(RUST_TARGETS),
        "rustdoc_json_format": 57,
        "bootstrap": {
            "used": True,
            "environment": "RUSTC_BOOTSTRAP=1",
            "reason": (
                "Rust 1.96.0 requires the unstable rustdoc JSON output option. "
                "The compiler and rustdoc binaries remain pinned to 1.96.0."
            ),
            "limitation": (
                "The public-API oracle uses an unstable output format. It does not "
                "claim that stable rustdoc supports JSON without the bootstrap flag."
            ),
        },
    }


def normalize_source_path(path: str, source_root: Path) -> str:
    candidate = Path(path)
    try:
        relative = candidate.resolve().relative_to(source_root.resolve())
    except (OSError, ValueError) as error:
        raise InventoryError(f"CARGO_PATH_OUTSIDE_SOURCE:{path}") from error
    value = relative.as_posix()
    if not valid_path(value):
        fail("CARGO_PATH_INVALID", value)
    return value


def cargo_metadata(source_root: Path, toolchain: Mapping[str, Any]) -> dict[str, Any]:
    cargo_path = toolchain["tools"]["cargo"]["path_role"]
    cargo_binary = str(Path(toolchain["sysroot"]) / "bin" / "cargo")
    completed = command(
        [
            cargo_binary,
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ],
        cwd=source_root,
        timeout=60,
        maximum=MAX_COMMAND_OUTPUT_BYTES,
        environment={"CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never"},
        allow_stderr=True,
    )
    raw = strict_json(
        completed.stdout, label="cargo-metadata", maximum=MAX_COMMAND_OUTPUT_BYTES
    )
    packages_raw = raw.get("packages") if isinstance(raw, dict) else None
    members = raw.get("workspace_members") if isinstance(raw, dict) else None
    if not isinstance(packages_raw, list) or not isinstance(members, list):
        fail("CARGO_METADATA_SHAPE")
    packages: list[dict[str, Any]] = []
    for package in packages_raw:
        if not isinstance(package, dict):
            fail("CARGO_PACKAGE_SHAPE")
        targets: list[dict[str, Any]] = []
        for target in package.get("targets", []):
            if not isinstance(target, dict):
                fail("CARGO_TARGET_SHAPE")
            targets.append(
                {
                    "name": target.get("name"),
                    "kind": target.get("kind"),
                    "crate_types": target.get("crate_types"),
                    "required_features": target.get("required-features", []),
                    "src_path": normalize_source_path(
                        target.get("src_path", ""), source_root
                    ),
                    "edition": target.get("edition"),
                    "doctest": target.get("doctest"),
                    "test": target.get("test"),
                    "doc": target.get("doc"),
                }
            )
        targets.sort(key=lambda item: (item["name"], item["kind"], item["src_path"]))
        dependencies: list[dict[str, Any]] = []
        for dependency in package.get("dependencies", []):
            if not isinstance(dependency, dict):
                fail("CARGO_DEPENDENCY_SHAPE")
            dependencies.append(
                {
                    "name": dependency.get("name"),
                    "rename": dependency.get("rename"),
                    "source": dependency.get("source"),
                    "req": dependency.get("req"),
                    "kind": dependency.get("kind"),
                    "optional": dependency.get("optional"),
                    "uses_default_features": dependency.get("uses_default_features"),
                    "features": dependency.get("features"),
                    "target": dependency.get("target"),
                    "path": (
                        normalize_source_path(dependency["path"], source_root)
                        if dependency.get("path")
                        else None
                    ),
                }
            )
        dependencies.sort(
            key=lambda item: (
                item["name"] or "",
                item["kind"] or "",
                item["target"] or "",
                item["rename"] or "",
            )
        )
        package_record = {
            "name": package.get("name"),
            "version": package.get("version"),
            "id": f"{package.get('name')}@{package.get('version')}",
            "manifest_path": normalize_source_path(
                package.get("manifest_path", ""), source_root
            ),
            "authors": package.get("authors"),
            "description": package.get("description"),
            "edition": package.get("edition"),
            "rust_version": package.get("rust_version"),
            "license": package.get("license"),
            "repository": package.get("repository"),
            "publish": package.get("publish"),
            "features": package.get("features"),
            "targets": targets,
            "dependencies": dependencies,
        }
        packages.append(package_record)
    packages.sort(key=lambda item: item["name"])
    workspace_member_names = sorted(
        package.get("name") for package in packages_raw if package.get("id") in members
    )
    target_counts = Counter(
        kind
        for package in packages
        for target in package["targets"]
        for kind in target["kind"]
    )
    feature_rows = [
        {"package": package["name"], "feature": name, "members": members}
        for package in packages
        for name, members in sorted(package["features"].items())
    ]
    if (
        len(packages) != 16
        or sum(len(item["targets"]) for item in packages) != 22
        or target_counts != Counter({"lib": 15, "bin": 2, "example": 4, "test": 1})
        or len(feature_rows) != 8
    ):
        fail("CARGO_EXPECTED_CARDINALITY")
    workspace_manifest = tomllib.loads(
        (source_root / "Cargo.toml").read_text(encoding="utf-8")
    )
    workspace_package = workspace_manifest.get("workspace", {}).get("package", {})
    mismatch = {
        "observed": {
            "version": workspace_package.get("version"),
            "authors": workspace_package.get("authors"),
            "publish": workspace_package.get("publish"),
        },
        "release_target": RELEASE_TARGET,
        "expected_author": AUTHOR["name"],
        "is_release_metadata_aligned": False,
        "finding": (
            "The workspace still declares version 0.1.0-experimental, author Sepahead, "
            "and publish=false. These values do not declare the planned 0.9.0 release."
        ),
    }
    if mismatch["observed"] != {
        "version": "0.1.0-experimental",
        "authors": ["Sepahead"],
        "publish": False,
    }:
        fail("CARGO_DECLARED_MISMATCH_DRIFT")
    normalized = {
        "capture_command": [
            cargo_path,
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ],
        "packages": packages,
        "workspace_members": workspace_member_names,
        "feature_rows": feature_rows,
        "counts": {
            "packages": len(packages),
            "targets": sum(len(item["targets"]) for item in packages),
            "lib": target_counts["lib"],
            "bin": target_counts["bin"],
            "example": target_counts["example"],
            "test": target_counts["test"],
            "feature_rows": len(feature_rows),
        },
        "normalized_sha256": "",
    }
    normalized["normalized_sha256"] = sha256(
        canonical_json(
            {
                key: value
                for key, value in normalized.items()
                if key != "normalized_sha256"
            }
        )
    )
    return {"metadata": normalized, "declared_mismatch": mismatch}


def rust_api_configurations(package: Mapping[str, Any]) -> list[dict[str, Any]]:
    features = sorted(name for name in package["features"] if name != "default")
    configurations: list[dict[str, Any]] = [
        {"id": "DEFAULT", "arguments": []},
        {"id": "NO_DEFAULT", "arguments": ["--no-default-features"]},
    ]
    configurations.extend(
        {
            "id": f"FEATURE:{feature}",
            "arguments": ["--no-default-features", "--features", feature],
        }
        for feature in features
    )
    configurations.append({"id": "ALL_FEATURES", "arguments": ["--all-features"]})
    return configurations


def rustdoc_json_format(payload: bytes, label: str) -> int:
    value = strict_json(payload, label=label, maximum=MAX_AGGREGATE_BLOB_BYTES)
    if not isinstance(value, dict) or not isinstance(value.get("format_version"), int):
        fail("RUSTDOC_JSON_SHAPE", label)
    return value["format_version"]


def capture_public_api(
    source_root: Path,
    metadata: Mapping[str, Any],
    toolchain: Mapping[str, Any],
) -> dict[str, Any]:
    library_packages = [
        package
        for package in metadata["packages"]
        if any("lib" in target["kind"] for target in package["targets"])
    ]
    if len(library_packages) != 15:
        fail("RUST_LIBRARY_PACKAGE_COUNT")
    rustup = toolchain["rustup_path"]
    sysroot = Path(toolchain["sysroot"])
    public_api_binary = toolchain["cargo_public_api"]["path"]
    documents: dict[str, dict[str, Any]] = {}
    document_set_bytes = 0
    observations: list[dict[str, Any]] = []
    macro_names: set[str] = set()
    with tempfile.TemporaryDirectory(
        prefix="haldir-ch-t003-rustdoc-"
    ) as target_directory:
        target_root = Path(target_directory)
        for package in library_packages:
            lib_target = next(
                target for target in package["targets"] if "lib" in target["kind"]
            )
            crate_name = lib_target["name"].replace("-", "_")
            for target in RUST_TARGETS:
                for configuration in rust_api_configurations(package):
                    arguments = [
                        rustup,
                        "run",
                        PINNED_RUST_VERSION,
                        "cargo",
                        "rustdoc",
                        "--locked",
                        "--offline",
                        "-p",
                        package["name"],
                        "--lib",
                        "--target",
                        target,
                        *configuration["arguments"],
                        "--",
                        "-Z",
                        "unstable-options",
                        "--output-format",
                        "json",
                        "--document-hidden-items",
                        "--cap-lints",
                        "warn",
                    ]
                    environment = {
                        "CARGO_NET_OFFLINE": "true",
                        "CARGO_TERM_COLOR": "never",
                        "CARGO_TARGET_DIR": str(target_root),
                        "RUSTC": str(sysroot / "bin" / "rustc"),
                        "RUSTDOC": str(sysroot / "bin" / "rustdoc"),
                        "RUSTC_BOOTSTRAP": "1",
                        "RUSTDOCFLAGS": "--document-hidden-items",
                    }
                    if target == "x86_64-unknown-linux-gnu":
                        zig_path = toolchain["cross_compiler"]["path"]
                        environment.update(
                            {
                                "CC_x86_64_unknown_linux_gnu": (
                                    f"{zig_path} cc -target x86_64-linux-gnu"
                                ),
                                "AR_x86_64_unknown_linux_gnu": f"{zig_path} ar",
                                "CRATE_CC_NO_DEFAULTS": "1",
                                "ZIG_GLOBAL_CACHE_DIR": str(
                                    target_root / "zig-global-cache"
                                ),
                                "ZIG_LOCAL_CACHE_DIR": str(
                                    target_root / "zig-local-cache"
                                ),
                            }
                        )
                    started = time.monotonic()
                    command(
                        arguments,
                        cwd=source_root,
                        timeout=600,
                        maximum=MAX_COMMAND_OUTPUT_BYTES,
                        environment=environment,
                        allow_stderr=True,
                    )
                    rustdoc_path = target_root / target / "doc" / f"{crate_name}.json"
                    if not rustdoc_path.is_file():
                        fail(
                            "RUSTDOC_JSON_MISSING",
                            f"{package['name']}:{target}:{configuration['id']}",
                        )
                    rustdoc_payload = bounded_path_bytes(
                        rustdoc_path.resolve(strict=True),
                        maximum=MAX_AGGREGATE_BLOB_BYTES,
                        label="RUSTDOC_JSON",
                    )
                    format_version = rustdoc_json_format(
                        rustdoc_payload,
                        f"{package['name']}:{target}:{configuration['id']}",
                    )
                    if format_version != toolchain["rustdoc_json_format"]:
                        fail("RUSTDOC_JSON_FORMAT", str(format_version))
                    rendered = command(
                        [
                            public_api_binary,
                            "--rustdoc-json",
                            str(rustdoc_path),
                            "--color",
                            "never",
                        ],
                        cwd=source_root,
                        timeout=120,
                        maximum=MAX_COMMAND_OUTPUT_BYTES,
                    ).stdout
                    try:
                        text = rendered.decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise InventoryError("PUBLIC_API_UTF8") from error
                    if not text.endswith("\n"):
                        fail("PUBLIC_API_NEWLINE")
                    document_digest = sha256(rendered)
                    if document_digest not in documents:
                        compressed = gzip.compress(rendered, compresslevel=9, mtime=0)
                        encoded = base64.b64encode(compressed).decode("ascii")
                        document = {
                            "sha256": document_digest,
                            "bytes": len(rendered),
                            "lines": len(text.splitlines()),
                            "encoding": "gzip+base64",
                            "encoded_bytes": len(compressed),
                            "encoded_sha256": sha256(compressed),
                            "listing_gzip_base64": encoded,
                        }
                        document_bytes = len(canonical_json(document))
                        if (
                            document_set_bytes + document_bytes
                            > MAX_PUBLIC_API_DOCUMENT_SET_BYTES
                        ):
                            fail("PUBLIC_API_DOCUMENT_SET_SIZE")
                        document_set_bytes += document_bytes
                        documents[document_digest] = document
                    if package["name"] == "haldir-contracts":
                        for line in text.splitlines():
                            match = re.fullmatch(
                                r"pub macro haldir_contracts::([A-Za-z0-9_]+)!", line
                            )
                            if match:
                                macro_names.add(match.group(1))
                    observations.append(
                        {
                            "package": package["name"],
                            "target": target,
                            "configuration": configuration["id"],
                            "feature_arguments": configuration["arguments"],
                            "rustdoc_json_format": format_version,
                            "api_document_sha256": document_digest,
                            "api_lines": len(text.splitlines()),
                            "capture_elapsed_ms_informational": int(
                                (time.monotonic() - started) * 1_000
                            ),
                        }
                    )
    # Elapsed time is not source evidence and would make the product unstable.
    for observation in observations:
        observation.pop("capture_elapsed_ms_informational", None)
    if tuple(sorted(macro_names)) != tuple(sorted(EXPECTED_EXPORTED_MACROS)):
        fail("RUST_EXPORTED_MACRO_INVARIANT")
    observations.sort(
        key=lambda item: (item["package"], item["target"], item["configuration"])
    )
    document_list = sorted(documents.values(), key=lambda item: item["sha256"])
    expected_observations = sum(
        len(rust_api_configurations(package)) * len(RUST_TARGETS)
        for package in library_packages
    )
    if len(observations) != expected_observations:
        fail("RUST_API_OBSERVATION_COUNT")
    return {
        "policy": {
            "oracle": "PINNED_RUSTDOC_JSON_RENDERED_BY_CARGO_PUBLIC_API",
            "compiler_resolved": True,
            "document_hidden_items": True,
            "locked": True,
            "offline": True,
            "cargo_public_api_version": PINNED_CARGO_PUBLIC_API_VERSION,
            "cargo_public_api_binary_sha256": (
                "acdc7b1733d52476fc2ce456a2a0292b82c367566fe0d2ab15c12b99974c8d24"
            ),
            "linux_c_cross_compiler": f"zig {PINNED_ZIG_VERSION}",
            "linux_c_cross_compiler_binary_sha256": PINNED_ZIG_SHA256,
            "rust_toolchain": PINNED_RUST_VERSION,
            "required_environment": [
                "CARGO_NET_OFFLINE=true",
                (
                    "CC_x86_64_unknown_linux_gnu=<pinned-zig> cc "
                    "-target x86_64-linux-gnu"
                ),
                "CRATE_CC_NO_DEFAULTS=1",
                "RUSTC_BOOTSTRAP=1",
                "RUSTDOCFLAGS=--document-hidden-items",
            ],
            "required_arguments": [
                "--locked",
                "--offline",
                "--document-hidden-items",
            ],
            "targets": list(RUST_TARGETS),
            "configuration_rule": (
                "DEFAULT, NO_DEFAULT, each non-default named package feature, and "
                "ALL_FEATURES for every library package and target"
            ),
            "listing_simplification": "NONE",
            "listing_encoding": "DETERMINISTIC_GZIP_MTIME_ZERO_THEN_BASE64",
            "deduplication": "EXACT_RENDERED_LISTING_SHA256",
        },
        "documents": document_list,
        "observations": observations,
        "macro_invariant": {
            "package": "haldir-contracts",
            "expected": list(EXPECTED_EXPORTED_MACROS),
            "observed": sorted(macro_names),
            "result": "PASS",
        },
        "counts": {
            "library_packages": len(library_packages),
            "targets": len(RUST_TARGETS),
            "observations": len(observations),
            "unique_documents": len(document_list),
        },
        "documents_sha256": sha256(canonical_json(document_list)),
        "observations_sha256": sha256(canonical_json(observations)),
    }


def python_cli_facts(path: str, payload: bytes, mode: str) -> dict[str, Any] | None:
    try:
        text = payload.decode("utf-8")
        tree = ast.parse(text, filename=path)
    except (UnicodeDecodeError, SyntaxError) as error:
        raise InventoryError(f"PYTHON_SOURCE_INVALID:{path}") from error
    has_main_guard = False
    argument_parser_calls = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            left = node.test.left
            comparators = node.test.comparators
            if (
                isinstance(left, ast.Name)
                and left.id == "__name__"
                and len(comparators) == 1
                and isinstance(comparators[0], ast.Constant)
                and comparators[0].value == "__main__"
            ):
                has_main_guard = True
        if isinstance(node, ast.Call):
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and function.attr == "ArgumentParser"
            ) or (isinstance(function, ast.Name) and function.id == "ArgumentParser"):
                argument_parser_calls += 1
    executable_shebang = mode == "100755" and text.startswith("#!")
    if not has_main_guard and not executable_shebang:
        return None
    parser = (
        "ARGPARSE" if argument_parser_calls else "SOURCE_DEFINED_OR_NO_ARGUMENT_PARSER"
    )
    return {
        "path": path,
        "sha256": sha256(payload),
        "entry_kind": "PYTHON",
        "has_main_guard": has_main_guard,
        "executable_shebang": executable_shebang,
        "parser": parser,
        "argument_parser_calls": argument_parser_calls,
    }


def just_recipes(payload: bytes) -> list[str]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise InventoryError("JUSTFILE_UTF8") from error
    recipes: list[str] = []
    for line in lines:
        if (
            not line
            or line[0].isspace()
            or line.startswith(("#", "@", "set ", "export "))
        ):
            continue
        match = re.match(r"([A-Za-z0-9][A-Za-z0-9_-]*)(?:\s+[^:]*)?\s*:(?!=)", line)
        if match:
            recipes.append(match.group(1))
    if len(recipes) != len(set(recipes)):
        fail("JUST_RECIPE_DUPLICATE")
    return sorted(recipes)


def runtime_record(
    argv: list[str], completed: subprocess.CompletedProcess[bytes]
) -> dict[str, Any]:
    for label, payload in (("stdout", completed.stdout), ("stderr", completed.stderr)):
        if b"\x00" in payload:
            fail("CLI_RUNTIME_BINARY_OUTPUT", label)
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise InventoryError(f"CLI_RUNTIME_UTF8:{label}") from error
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("utf-8"),
        "stderr": completed.stderr.decode("utf-8"),
        "stdout_sha256": sha256(completed.stdout),
        "stderr_sha256": sha256(completed.stderr),
    }


def run_observed(
    argv: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
    timeout: int = 30,
) -> subprocess.CompletedProcess[bytes]:
    completed = command(
        argv,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
        maximum=MAX_COMMAND_OUTPUT_BYTES,
        allow_stderr=True,
        require_success=False,
    )
    if len(completed.stdout) + len(completed.stderr) > MAX_COMMAND_OUTPUT_BYTES:
        fail("CLI_RUNTIME_OUTPUT_LIMIT")
    return completed


def capture_cli_inventory(
    source_root: Path,
    records: Sequence[dict[str, Any]],
    blobs: Mapping[str, bytes],
    metadata: Mapping[str, Any],
    toolchain: Mapping[str, Any],
) -> dict[str, Any]:
    python_entries: list[dict[str, Any]] = []
    shell_entries: list[dict[str, Any]] = []
    for record in records:
        path = record["path"]
        payload = blobs[path]
        if path.startswith("tools/") and path.endswith(".py"):
            facts = python_cli_facts(path, payload, record["git_mode"])
            if facts is not None:
                python_entries.append(facts)
        if path.startswith("tools/") and path.endswith(".sh"):
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise InventoryError(f"SHELL_UTF8:{path}") from error
            if not text.startswith("#!"):
                fail("SHELL_SHEBANG", path)
            shell_entries.append(
                {
                    "path": path,
                    "sha256": record["sha256"],
                    "entry_kind": "SHELL",
                    "executable": record["git_mode"] == "100755",
                }
            )
    python_entries.sort(key=lambda item: item["path"])
    shell_entries.sort(key=lambda item: item["path"])
    parser_entry_count = sum(item["parser"] == "ARGPARSE" for item in python_entries)
    if len(python_entries) != 45 or parser_entry_count != 16:
        fail(
            "PYTHON_CLI_EXPECTED_CARDINALITY",
            f"{len(python_entries)}:{parser_entry_count}",
        )
    cargo_targets = [
        {
            "package": package["name"],
            "name": target["name"],
            "kind": target["kind"],
            "required_features": target["required_features"],
            "src_path": target["src_path"],
        }
        for package in metadata["packages"]
        for target in package["targets"]
    ]
    cargo_targets.sort(key=lambda item: (item["package"], item["name"], item["kind"]))
    if len(cargo_targets) != 22:
        fail("CLI_CARGO_TARGET_COUNT")
    recipes = just_recipes(blobs["justfile"])
    cargo_binary = str(Path(toolchain["sysroot"]) / "bin" / "cargo")
    rust_environment = {
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "RUSTC": str(Path(toolchain["sysroot"]) / "bin" / "rustc"),
        "RUSTDOC": str(Path(toolchain["sysroot"]) / "bin" / "rustdoc"),
    }
    with tempfile.TemporaryDirectory(prefix="haldir-ch-t003-cli-") as target_directory:
        rust_environment["CARGO_TARGET_DIR"] = target_directory
        command(
            [
                cargo_binary,
                "build",
                "--locked",
                "--offline",
                "--target",
                "aarch64-apple-darwin",
                "-p",
                "haldir-gate",
                "--bin",
                "haldir-gate",
                "-p",
                "haldir-ctl",
                "--bin",
                "haldir-ctl",
            ],
            cwd=source_root,
            timeout=600,
            environment=rust_environment,
            allow_stderr=True,
        )
        binary_root = Path(target_directory) / "aarch64-apple-darwin" / "debug"
        gate = str(binary_root / "haldir-gate")
        ctl = str(binary_root / "haldir-ctl")
        scenarios = [
            ("gate_no_arguments", gate, []),
            ("gate_version", gate, ["--version"]),
            ("gate_version_trailing_argument", gate, ["--version", "ignored"]),
            ("gate_check_config", gate, ["--check-config"]),
            (
                "gate_check_config_trailing_argument",
                gate,
                ["--check-config", "ignored"],
            ),
            ("gate_unknown_argument", gate, ["--unknown"]),
            ("ctl_no_arguments", ctl, []),
            ("ctl_argument", ctl, ["--version"]),
        ]
        runtime: list[dict[str, Any]] = []
        for scenario, binary, arguments in scenarios:
            completed = run_observed(
                [binary, *arguments],
                cwd=source_root,
                environment=rust_environment,
            )
            runtime.append(
                {
                    "scenario": scenario,
                    **runtime_record(
                        [PurePosixPath(binary).name, *arguments],
                        completed,
                    ),
                }
            )
    expected_codes = {
        "gate_no_arguments": 2,
        "gate_version": 0,
        "gate_version_trailing_argument": 0,
        "gate_check_config": 0,
        "gate_check_config_trailing_argument": 0,
        "gate_unknown_argument": 2,
        "ctl_no_arguments": 2,
        "ctl_argument": 2,
    }
    if {item["scenario"]: item["exit_code"] for item in runtime} != expected_codes:
        fail("CLI_RUNTIME_EXIT_CODES")
    version = next(item for item in runtime if item["scenario"] == "gate_version")
    version_trailing = next(
        item for item in runtime if item["scenario"] == "gate_version_trailing_argument"
    )
    if (
        version["stdout"] != version_trailing["stdout"]
        or version["stderr"] != version_trailing["stderr"]
    ):
        fail("GATE_TRAILING_ARGUMENT_QUIRK")
    return {
        "cargo_targets": cargo_targets,
        "python_entry_points": python_entries,
        "shell_entry_points": shell_entries,
        "just_recipes": recipes,
        "runtime_observations": runtime,
        "candidate_projection": {
            "candidate_files_are_not_in_freeze_counts": [
                PRODUCT_PATH,
                PRODUCT_TESTS_PATH,
            ],
            "rule": "Recompute candidate counts at I; do not add them to the F oracle.",
        },
        "counts": {
            "cargo_targets": len(cargo_targets),
            "python_entry_points": len(python_entries),
            "python_argument_parser_entry_points": parser_entry_count,
            "shell_entry_points": len(shell_entries),
            "just_recipes": len(recipes),
            "runtime_observations": len(runtime),
        },
    }


def capture_ipc(blobs: Mapping[str, bytes]) -> dict[str, Any]:
    profile_path = "deploy/secure-reference-v1/profile.json"
    profile = strict_json(blobs[profile_path], label=profile_path)
    routes = profile.get("routes") if isinstance(profile, dict) else None
    principals = profile.get("principals") if isinstance(profile, dict) else None
    if (
        not isinstance(routes, dict)
        or len(routes) != 17
        or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in routes.items()
        )
        or not isinstance(principals, dict)
        or len(principals) != 8
    ):
        fail("IPC_PROFILE_CARDINALITY")
    builder_families = [
        {
            "family": "intent",
            "method": "HaldirKeys::intent",
            "fixture_route_ids": ["controller_a_intent", "controller_b_intent"],
            "implementation_status": "BUILDER_AVAILABLE",
        },
        {
            "family": "decision",
            "method": "HaldirKeys::decision",
            "fixture_route_ids": ["decision_evidence"],
            "implementation_status": "BUILDER_AVAILABLE",
        },
        {
            "family": "challenge",
            "method": "HaldirKeys::challenge",
            "fixture_route_ids": ["gate_challenge"],
            "implementation_status": "BUILDER_AVAILABLE",
        },
        {
            "family": "state",
            "method": "HaldirKeys::state",
            "fixture_route_ids": ["state_pose"],
            "implementation_status": "BUILDER_AVAILABLE",
        },
        {
            "family": "application",
            "method": "HaldirKeys::application",
            "fixture_route_ids": ["application_evidence"],
            "implementation_status": "BUILDER_AVAILABLE",
        },
        {
            "family": "final_command",
            "method": "HaldirKeys::final_command",
            "fixture_route_ids": ["final_command"],
            "implementation_status": "BUILDER_AVAILABLE",
        },
    ]
    covered = sorted(
        route for family in builder_families for route in family["fixture_route_ids"]
    )
    if len(builder_families) != 6 or len(covered) != 7:
        fail("IPC_BUILDER_CARDINALITY")
    live_bound = [
        {
            "family": "intent",
            "role": "SUBSCRIBER",
            "source": "crates/haldir-transport-zenoh/src/live.rs",
            "type": "IntentIngress",
            "status": "LIVE_BOUND",
        },
        {
            "family": "final_command",
            "role": "PUBLISHER",
            "source": "crates/haldir-transport-zenoh/src/live.rs",
            "type": "FinalCommandPublisher",
            "status": "LIVE_BOUND",
        },
    ]
    profile_not_live = sorted(
        set(routes) - {"controller_a_intent", "controller_b_intent", "final_command"}
    )
    direct_ecosystem_dependencies = {
        name: any(
            name in payload.decode("utf-8", errors="ignore").casefold()
            for payload in blobs.values()
        )
        for name in ("engram", "galadriel", "prisoma")
    }
    absent_protocols = [
        "DDS",
        "FFI",
        "GRPC",
        "HTTP",
        "MAVROS",
        "ROS",
        "SHARED_MEMORY",
    ]
    return {
        "profile": {
            "path": profile_path,
            "sha256": sha256(blobs[profile_path]),
            "profile_id": profile.get("profile_id"),
            "realm": profile.get("realm"),
            "session_id": profile.get("session_id"),
            "routes": [
                {
                    "id": key,
                    "key_expression": routes[key],
                    "status": "PROFILE_DECLARED",
                }
                for key in sorted(routes)
            ],
            "principals": [
                {"id": key, **principals[key]} for key in sorted(principals)
            ],
        },
        "builder_families": builder_families,
        "live_bound_families": live_bound,
        "profile_routes_without_live_binding": profile_not_live,
        "absent_protocols": absent_protocols,
        "documentation_mentions_observed": direct_ecosystem_dependencies,
        "boundary": {
            "profile_declaration_is_not_live_binding": True,
            "builder_availability_is_not_live_binding": True,
            "live_transport_feature_default": False,
            "live_transport_feature": "live-zenoh",
            "remote_identity_boundary": (
                "A received sample has a Remote route and payload identity, but it "
                "does not expose the peer certificate identity."
            ),
            "maximum_complete_route_bytes": 256,
            "maximum_identifier_segment_bytes": 64,
        },
        "counts": {
            "profile_routes": len(routes),
            "principals": len(principals),
            "builder_families": len(builder_families),
            "builder_fixture_route_ids": len(covered),
            "live_bound_families": len(live_bound),
            "profile_routes_without_live_binding": len(profile_not_live),
        },
    }


def source_line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def json_top_level_type(value: Any) -> str:
    if isinstance(value, dict):
        return "OBJECT"
    if isinstance(value, list):
        return "ARRAY"
    if isinstance(value, str):
        return "STRING"
    if isinstance(value, bool):
        return "BOOLEAN"
    if value is None:
        return "NULL"
    if isinstance(value, (int, float)):
        return "NUMBER"
    fail("JSON_TOP_LEVEL_TYPE")


def capture_schema_inventory(
    records: Sequence[dict[str, Any]], blobs: Mapping[str, bytes]
) -> dict[str, Any]:
    top_level_messages: list[dict[str, Any]] = []
    nested_canonical_values: list[dict[str, Any]] = []
    tagged_enums: list[dict[str, Any]] = []
    handwritten_contracts: list[dict[str, Any]] = []
    message_pattern = re.compile(
        r"(?m)^\s*pub\s+struct\s+([A-Za-z0-9_]+)\s+kind\s+\"([^\"]+)\"\s*\{"
    )
    nested_pattern = re.compile(r"(?m)^\s*pub\s+struct\s+([A-Za-z0-9_]+)\s*\{")
    tagged_pattern = re.compile(r"(?m)^\s*pub\s+enum\s+([A-Za-z0-9_]+)\s*\{")
    for record in records:
        path = record["path"]
        if not path.endswith(".rs"):
            continue
        text = blobs[path].decode("utf-8")
        for match in message_pattern.finditer(text):
            start = match.end()
            closing = text.find("\n}", start)
            if closing < 0:
                fail("CANONICAL_MESSAGE_BLOCK", path)
            block = text[start:closing]
            tags = [
                {
                    "presence": item.group(1),
                    "key": int(item.group(2)),
                    "field": item.group(3),
                }
                for item in re.finditer(
                    r"(?m)^\s*(req|opt)\s+(\d+)\s+([A-Za-z0-9_]+)\s*:",
                    block,
                )
            ]
            if not tags or len({item["key"] for item in tags}) != len(tags):
                fail("CANONICAL_MESSAGE_TAGS", match.group(1))
            top_level_messages.append(
                {
                    "name": match.group(1),
                    "kind": match.group(2),
                    "path": path,
                    "line": source_line_number(text, match.start()),
                    "key_tags": tags,
                }
            )
        # Macro invocations without a kind are nested CanonicalValue records.
        for macro_match in re.finditer(r"(?m)^\s*canonical_struct!\s*\{", text):
            end = text.find("\n}", macro_match.end())
            if end < 0:
                continue
            block = text[macro_match.end() : end]
            match = nested_pattern.search(block)
            if match and " kind " not in block[match.start() : match.end() + 128]:
                nested_canonical_values.append(
                    {
                        "name": match.group(1),
                        "path": path,
                        "line": source_line_number(text, macro_match.start()),
                    }
                )
        for macro_match in re.finditer(r"(?m)^\s*tagged_enum!\s*\{", text):
            end = text.find("\n}", macro_match.end())
            if end < 0:
                continue
            block = text[macro_match.end() : end]
            match = tagged_pattern.search(block)
            if match:
                tagged_enums.append(
                    {
                        "name": match.group(1),
                        "path": path,
                        "line": source_line_number(text, macro_match.start()),
                    }
                )
        for trait_name in ("CanonicalValue", "CanonicalMessage", "Validate"):
            if trait_name in text:
                handwritten_contracts.append(
                    {
                        "trait": trait_name,
                        "path": path,
                        "source_sha256": record["sha256"],
                    }
                )
    top_level_messages.sort(key=lambda item: item["name"])
    nested_canonical_values.sort(
        key=lambda item: (item["name"], item["path"], item["line"])
    )
    tagged_enums.sort(key=lambda item: (item["name"], item["path"], item["line"]))
    handwritten_contracts.sort(key=lambda item: (item["trait"], item["path"]))
    expected_names = {
        "GateChallengeV1",
        "HaldirIntentV1",
        "MissionLeaseV1",
        "PublicationStageEventV1",
        "DecisionReceiptV1",
        "AuthorityRevocationV1",
        "GateStatusV1",
        "AdmissionRecordV1",
        "ControllerBundleManifestV1",
        "DeploymentPackageV1",
        "NcpCompatibilityArtifactV1",
    }
    if (
        len(top_level_messages) != 11
        or {item["name"] for item in top_level_messages} != expected_names
        or len({item["kind"] for item in top_level_messages}) != 11
    ):
        fail("CANONICAL_TOP_LEVEL_MESSAGE_INVARIANT")
    json_records: list[dict[str, Any]] = []
    for record in records:
        path = record["path"]
        if not path.casefold().endswith(".json"):
            continue
        value = strict_json(blobs[path], label=path)
        if path.casefold().endswith(".schema.json") or (
            isinstance(value, dict)
            and "$schema" in value
            and ("properties" in value or "$defs" in value)
        ):
            kind = "DEFINITION"
        elif path.startswith(("evidence/11-", "evidence/12-")):
            kind = "LIVE_EVIDENCE_INSTANCE"
        elif "/tests/data/" in f"/{path}" or path.startswith("contracts/vectors/"):
            kind = "VERIFIED_VECTOR"
        elif path.startswith(("release/", "audit/", "evidence/")):
            kind = "RETAINED_INSTANCE"
        else:
            kind = "ORDINARY_JSON_RECORD"
        json_records.append(
            {
                "path": path,
                "sha256": record["sha256"],
                "kind": kind,
                "top_level_type": json_top_level_type(value),
                "schema_version": value.get("schema_version")
                if isinstance(value, dict)
                else None,
            }
        )
    json_records.sort(key=lambda item: item["path"])
    definitions = [item for item in json_records if item["kind"] == "DEFINITION"]
    instances = [item for item in json_records if item["kind"] != "DEFINITION"]
    return {
        "canonical_messages": top_level_messages,
        "nested_canonical_values": nested_canonical_values,
        "tagged_enums": tagged_enums,
        "handwritten_contract_traits": handwritten_contracts,
        "json_records": json_records,
        "boundary": {
            "json_instance_is_not_schema_definition": True,
            "nested_canonical_value_is_not_top_level_message": True,
            "retained_machine_record_is_not_runtime_validation": True,
        },
        "counts": {
            "canonical_messages": len(top_level_messages),
            "nested_canonical_values": len(nested_canonical_values),
            "tagged_enums": len(tagged_enums),
            "json_schema_definitions": len(definitions),
            "json_instances": len(instances),
        },
    }


def capture_documentation(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    markdown = sorted(
        item["path"] for item in records if item["path"].casefold().endswith(".md")
    )
    baseline_sources = sorted(
        item["path"]
        for item in records
        if item["path"].casefold().endswith((".md", ".rst", ".txt"))
    )
    if len(markdown) != 48 or len(baseline_sources) != 49:
        fail(
            "DOCUMENTATION_EXPECTED_CARDINALITY",
            f"{len(markdown)}:{len(baseline_sources)}",
        )
    required_root_documents = {
        "README.md": "PRESENT",
        "CONTRIBUTING.md": "PRESENT",
        "SECURITY.md": "PRESENT",
        "AGENTS.md": "MISSING_PLANNED_LATER_TASK",
        "CLAUDE.md": "MISSING_PLANNED_LATER_TASK",
        "CHANGELOG.md": "MISSING_PLANNED_LATER_TASK",
    }
    observed = {item["path"] for item in records}
    for path, status in required_root_documents.items():
        if (path in observed) != (status == "PRESENT"):
            fail("ROOT_DOCUMENT_STATUS", path)
    return {
        "markdown_paths": markdown,
        "baseline_text_paths": baseline_sources,
        "required_root_documents": [
            {"path": path, "status": status}
            for path, status in sorted(required_root_documents.items())
        ],
        "other_documentation_surfaces": {
            "rustdoc": "CAPTURED_IN_CARGO_PUBLIC_API_ORACLE",
            "cargo_package_descriptions": "CAPTURED_IN_CARGO_METADATA",
            "cli_help_and_errors": "SOURCE_INVENTORIED_AND_CRITICAL_RUNTIME_OUTPUT_CAPTURED",
            "configuration_comments": "BOUND_BY_COMPLETE_FILE_INVENTORY",
            "github_description": "CAPTURED_IN_GITHUB_METADATA_WHEN_OBSERVABLE",
        },
        "counts": {
            "markdown": len(markdown),
            "baseline_md_rst_txt": len(baseline_sources),
            "required_root_present": sum(
                item == "PRESENT" for item in required_root_documents.values()
            ),
            "required_root_missing": sum(
                item != "PRESENT" for item in required_root_documents.values()
            ),
        },
    }


def open_relative_parent(
    root_descriptor: int,
    path: str,
    *,
    create: bool,
    created_directories: list[tuple[str, int, int]] | None = None,
) -> tuple[int, str]:
    if not valid_path(path):
        fail("RELATIVE_PATH", path)
    parts = PurePosixPath(path).parts
    descriptor = os.dup(root_descriptor)
    try:
        for index, part in enumerate(parts[:-1]):
            relative = "/".join(parts[: index + 1])
            try:
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                if created_directories is not None:
                    status = os.fstat(child)
                    created_directories.append((relative, status.st_dev, status.st_ino))
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        raise InventoryError(f"RELATIVE_PARENT:{path}") from error
    return descriptor, parts[-1]


def read_regular_at(
    parent_descriptor: int,
    name: str,
    *,
    maximum: int,
    label: str,
) -> tuple[bytes, tuple[int, int, int, int, int, int]]:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            fail(f"{label}_TYPE_OR_SIZE")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum:
                fail(f"{label}_SIZE")
        after = os.fstat(descriptor)
    except OSError as error:
        raise InventoryError(f"{label}_READ") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = (
        before.st_mode,
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    if observed != before.st_size or identity != (
        after.st_mode,
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        fail(f"{label}_CHANGED")
    return b"".join(chunks), identity


def candidate_input_snapshot(repo: Path) -> dict[str, dict[str, Any]]:
    repo = repo.resolve(strict=True)
    root_descriptor = os.open(
        repo,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    result: dict[str, dict[str, Any]] = {}
    try:
        for path in (CLAIM_LEDGER_PATH, PRODUCT_PATH, PRODUCT_TESTS_PATH):
            parent_descriptor, name = open_relative_parent(
                root_descriptor, path, create=False
            )
            try:
                payload, identity = read_regular_at(
                    parent_descriptor,
                    name,
                    maximum=MAX_BLOB_BYTES,
                    label="CANDIDATE_FILE",
                )
            finally:
                os.close(parent_descriptor)
            result[path] = {"payload": payload, "identity": identity}
    finally:
        os.close(root_descriptor)
    return result


def revalidate_candidate_inputs(
    repo: Path, snapshot: Mapping[str, Mapping[str, Any]]
) -> None:
    if set(snapshot) != {CLAIM_LEDGER_PATH, PRODUCT_PATH, PRODUCT_TESTS_PATH}:
        fail("CANDIDATE_SNAPSHOT_SET")
    current = candidate_input_snapshot(repo)
    for path in sorted(snapshot):
        record = snapshot[path]
        if (
            set(record) != {"payload", "identity"}
            or current[path]["identity"] != record["identity"]
            or current[path]["payload"] != record["payload"]
        ):
            fail("CANDIDATE_INPUT_CHANGED", path)


def candidate_file(repo: Path, path: str) -> bytes:
    snapshot = candidate_input_snapshot(repo)
    if path not in snapshot:
        fail("CANDIDATE_FILE_PATH", path)
    return snapshot[path]["payload"]


def candidate_implementation(
    repo: Path,
    freeze_paths: set[str],
    snapshot: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if set(IMPLEMENTATION_PLAN) & freeze_paths != {CLAIM_LEDGER_PATH}:
        fail("CANDIDATE_FREEZE_OVERLAP")
    if snapshot is None:
        snapshot = candidate_input_snapshot(repo)
    if set(snapshot) != {CLAIM_LEDGER_PATH, PRODUCT_PATH, PRODUCT_TESTS_PATH}:
        fail("CANDIDATE_SNAPSHOT_SET")
    records: list[dict[str, Any]] = []
    for path in sorted(IMPLEMENTATION_PLAN):
        change = IMPLEMENTATION_PLAN[path]
        if path in OUTPUT_PATHS:
            record = {
                "path": path,
                "change": change,
                "binding_kind": "NO_INNER_DIGEST",
                "sha256": None,
                "bytes": None,
            }
        else:
            payload = snapshot[path]["payload"]
            record = {
                "path": path,
                "change": change,
                "binding_kind": "EXACT_CANDIDATE_BYTES",
                "sha256": sha256(payload),
                "bytes": len(payload),
            }
        records.append(record)
    if (
        len(records) != 9
        or sum(item["change"] == "A" for item in records) != 8
        or sum(item["change"] == "M" for item in records) != 1
    ):
        fail("CANDIDATE_PLAN_CARDINALITY")
    return {
        "records": records,
        "paths_sha256": sha256(canonical_json([item["path"] for item in records])),
        "records_sha256": sha256(canonical_json(records)),
        "expected_implementation_regular_blobs": len(freeze_paths) + 8,
        "cycle_boundary": (
            "The six generated products identify their output paths but do not "
            "contain their own digest. The composition product binds the five siblings."
        ),
    }


def parse_claim_rows(payload: bytes) -> list[dict[str, str]]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise InventoryError("CLAIM_LEDGER_UTF8") from error
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        if not line.startswith("| CL-"):
            continue
        body = line[1:-1] if line.endswith("|") else line[1:]
        parts = [part.strip() for part in body.split("|")]
        status_positions = [
            index for index, part in enumerate(parts) if part in CLAIM_STATUSES
        ]
        if len(status_positions) != 1:
            fail("CLAIM_ROW_STATUS", parts[0] if parts else "")
        status_index = status_positions[0]
        if status_index < 2 or status_index >= len(parts) - 1:
            fail("CLAIM_ROW_COLUMNS", parts[0])
        claim_id = parts[0]
        statement = "|".join(parts[1:status_index]).strip()
        evidence = "|".join(parts[status_index + 1 :]).strip()
        if (
            CLAIM_ID_PATTERN.fullmatch(claim_id) is None
            or claim_id in seen
            or not statement
            or not evidence
        ):
            fail("CLAIM_ROW_INVALID", claim_id)
        seen.add(claim_id)
        rows.append(
            {
                "id": claim_id,
                "statement": statement,
                "status": parts[status_index],
                "evidence": evidence,
                "statement_sha256": sha256(statement.encode("utf-8")),
                "evidence_sha256": sha256(evidence.encode("utf-8")),
            }
        )
    rows.sort(key=lambda item: item["id"])
    if len(rows) != 52:
        fail("CLAIM_ROW_COUNT", str(len(rows)))
    return rows


def claim_type(claim_id: str) -> str:
    if any(word in claim_id for word in ("PUBLICATION", "EVIDENCE")):
        return "EVIDENCE_OR_PUBLICATION"
    if any(word in claim_id for word in ("NCP", "TRANSPORT", "ROUTE", "WIRE")):
        return "INTERFACE_OR_INTEROPERABILITY"
    if any(word in claim_id for word in ("FORMAL", "MODEL", "INVARIANT")):
        return "FORMAL_OR_MODEL"
    if any(
        word in claim_id
        for word in ("SECURITY", "AUTHORITY", "CRYPTO", "ACL", "REVOCATION", "POLICY")
    ):
        return "SECURITY_OR_AUTHORITY"
    if any(word in claim_id for word in ("DEPLOY", "LIVE", "FIELD")):
        return "DEPLOYMENT_OR_RUNTIME"
    return "IMPLEMENTATION"


MINIMUM_EVIDENCE = {
    "EVIDENCE_OR_PUBLICATION": [
        "BOUND_SOURCE_ARTIFACT",
        "REPRODUCIBLE_VERIFIER",
        "NON_SUBSTITUTION_BOUNDARY",
    ],
    "INTERFACE_OR_INTEROPERABILITY": [
        "BOUND_INTERFACE_DEFINITION",
        "CONFORMANCE_OR_NEGATIVE_TEST",
        "VERSION_IDENTITY",
    ],
    "FORMAL_OR_MODEL": [
        "BOUND_MODEL",
        "PINNED_CHECKER_RESULT",
        "MODEL_TO_IMPLEMENTATION_LIMITATION",
    ],
    "SECURITY_OR_AUTHORITY": [
        "BOUND_IMPLEMENTATION",
        "ADVERSARIAL_OR_NEGATIVE_TEST",
        "EXPLICIT_ASSUMPTIONS",
    ],
    "DEPLOYMENT_OR_RUNTIME": [
        "BOUND_IMPLEMENTATION",
        "RETAINED_RUNTIME_CAPTURE",
        "DEPLOYMENT_IDENTITY",
    ],
    "IMPLEMENTATION": [
        "BOUND_IMPLEMENTATION",
        "AUTOMATED_TEST_OR_STATIC_CHECK",
    ],
}
NON_SUBSTITUTES = {
    "EVIDENCE_OR_PUBLICATION": [
        "DOCUMENTATION_ALONE",
        "SELF_ASSERTION_ALONE",
        "UNBOUND_LOG",
    ],
    "INTERFACE_OR_INTEROPERABILITY": [
        "SOURCE_SHAPE_WITHOUT_COMPILER_OR_PARSER",
        "UNPINNED_UPSTREAM",
    ],
    "FORMAL_OR_MODEL": [
        "MODEL_RESULT_WITHOUT_REFINEMENT_BOUNDARY",
        "FINITE_MODEL_AS_FIELD_VALIDATION",
    ],
    "SECURITY_OR_AUTHORITY": [
        "HAPPY_PATH_TEST_ONLY",
        "CONFIGURATION_INTENT_AS_LIVE_ENFORCEMENT",
    ],
    "DEPLOYMENT_OR_RUNTIME": [
        "BUILDER_ONLY",
        "CONFIGURATION_ONLY",
        "SYNTHETIC_CAPTURE_AS_FIELD_EVIDENCE",
    ],
    "IMPLEMENTATION": [
        "DOCUMENTATION_ALONE",
        "UNREVIEWED_EXAMPLE",
    ],
}


def linked_claim_surfaces(
    row: Mapping[str, str],
    records: Sequence[dict[str, Any]],
) -> list[str]:
    combined = f"{row['statement']} {row['evidence']}"
    linked = {CLAIM_LEDGER_PATH}
    for record in records:
        if row["id"] in record["claim_ids"] or record["path"] in combined:
            linked.add(record["path"])
    return sorted(linked)


def observed_evidence_classes(
    row: Mapping[str, str],
    linked: Sequence[str],
    by_path: Mapping[str, dict[str, Any]],
) -> list[str]:
    result: set[str] = set()
    folded = row["evidence"].casefold()
    for path in linked:
        record = by_path.get(path)
        if record is None:
            continue
        result.add(record["classification"])
        result.update(record["surface_types"])
    if "test" in folded:
        result.add("TEST_REFERENCE")
    if "formal" in folded or "tlc" in folded:
        result.add("FORMAL_RESULT_REFERENCE")
    if "evidence/" in folded:
        result.add("RETAINED_EVIDENCE_REFERENCE")
    if row["status"] == "PROVEN":
        result.add("REPOSITORY_VERIFIED_CLAIM_ROW")
    return sorted(result)


def build_claim_tier_ledger(
    candidate_ledger: bytes,
    freeze_ledger: bytes,
    claims_state_payload: bytes,
    records: Sequence[dict[str, Any]],
    freeze_commit: str,
    freeze_tree: str,
) -> dict[str, Any]:
    rows = parse_claim_rows(candidate_ledger)
    freeze_rows = {item["id"]: item for item in parse_claim_rows(freeze_ledger)}
    state = strict_json(claims_state_payload, label=CLAIMS_STATE_PATH)
    active = set(state.get("active_claims", []))
    non_claimed = set(state.get("non_claimed_claims", []))
    removed = set(state.get("removed_claims", []))
    ids = {item["id"] for item in rows}
    if (
        ids != active | non_claimed | removed
        or active & non_claimed
        or active & removed
        or non_claimed & removed
    ):
        fail("CLAIM_STATE_PARTITION")
    by_path = {item["path"]: item for item in records}
    tier_records: list[dict[str, Any]] = []
    for row in rows:
        kind = claim_type(row["id"])
        linked = linked_claim_surfaces(row, records)
        tier = "VERIFIED" if row["status"] == "PROVEN" else "NOT_CLAIMED"
        if row["id"] in non_claimed or row["id"] in removed:
            tier = "NOT_CLAIMED"
        if row["id"] == NARROWED_CLAIM:
            if (
                row["status"] != "PROVEN"
                or tier != "VERIFIED"
                or row["statement"] != NARROWED_CLAIM_STATEMENT
                or freeze_rows[row["id"]]["statement_sha256"] == row["statement_sha256"]
                and freeze_rows[row["id"]]["evidence_sha256"] == row["evidence_sha256"]
            ):
                fail("NARROWED_CLAIM_ROW")
            narrowing = {
                "narrowed": True,
                "markdown_status_preserved": "PROVEN",
                "generated_tier_preserved": "VERIFIED",
                "scope": (
                    "Repository evidence primitives are verified. This does not "
                    "qualify a release, deployment, DOI, archive, or field result."
                ),
            }
        else:
            narrowing = None
        lifecycle = "ACTIVE"
        if row["id"] in non_claimed:
            lifecycle = "NOT_CLAIMED"
        elif row["id"] in removed:
            lifecycle = "REMOVED"
        if row["id"] == NARROWED_CLAIM:
            lifecycle = "ACTIVE_NARROWED_PENDING_ACTIVATION"
        tier_records.append(
            {
                **row,
                "lifecycle_disposition": lifecycle,
                "evidence_tier": tier,
                "claim_type": kind,
                "minimum_evidence": MINIMUM_EVIDENCE[kind],
                "observed_evidence_classes": observed_evidence_classes(
                    row, linked, by_path
                ),
                "non_substitutes": NON_SUBSTITUTES[kind],
                "linked_surfaces": linked,
                "release_qualified": False,
                "narrowing": narrowing,
            }
        )
    tier_counts = Counter(item["evidence_tier"] for item in tier_records)
    if tier_counts != Counter({"VERIFIED": 45, "NOT_CLAIMED": 7}):
        fail("CLAIM_TIER_EXPECTED_COUNTS", repr(tier_counts))
    surface_to_claims: dict[str, list[str]] = defaultdict(list)
    for item in tier_records:
        for path in item["linked_surfaces"]:
            surface_to_claims[path].append(item["id"])
    reverse = [
        {"surface": path, "claim_ids": sorted(claims)}
        for path, claims in sorted(surface_to_claims.items())
    ]
    return {
        "schema_version": "1.0.0",
        "schema_id": "haldir.ch-t003.claim-tier-ledger.v1",
        "task_id": TASK_ID,
        "release_target": RELEASE_TARGET,
        "author": AUTHOR,
        "persistent_identifier": None,
        "source": {
            "freeze_commit": freeze_commit,
            "freeze_tree": freeze_tree,
            "claim_ledger": {
                "path": CLAIM_LEDGER_PATH,
                "sha256": sha256(candidate_ledger),
                "bytes": len(candidate_ledger),
            },
            "prior_active_claims": {
                "path": CLAIMS_STATE_PATH,
                "sha256": sha256(claims_state_payload),
                "bytes": len(claims_state_payload),
            },
        },
        "tier_vocabulary": list(TIER_VOCABULARY),
        "policy": {
            "status_and_tier_are_distinct": True,
            "conservative_mapping": {
                "PROVEN": "VERIFIED",
                "ALL_OTHER_MARKDOWN_STATUSES": "NOT_CLAIMED",
            },
            "no_tier_above_verified_assigned": True,
        },
        "records": tier_records,
        "counts": {
            "claims": len(tier_records),
            "by_status": dict(
                sorted(Counter(item["status"] for item in tier_records).items())
            ),
            "by_tier": dict(sorted(tier_counts.items())),
            "narrowed": 1,
            "release_qualified": 0,
        },
        "bidirectional_links": {
            "claim_to_surface_complete": all(
                item["linked_surfaces"] for item in tier_records
            ),
            "surface_to_claims": reverse,
            "surface_to_claims_sha256": sha256(canonical_json(reverse)),
        },
        "records_sha256": sha256(canonical_json(tier_records)),
        "release_boundary": {
            "overall_status": "NO_GO",
            "release_qualified_claims": [],
            "tag_authorized": False,
            "github_release_authorized": False,
            "doi_authorized": False,
            "zenodo_authorized": False,
            "archive_authorized": False,
        },
        "result": "PASS",
    }


def file_binding(
    path: str,
    records_by_path: Mapping[str, dict[str, Any]],
    *,
    role: str | None = None,
) -> dict[str, Any]:
    record = records_by_path.get(path)
    if record is None:
        fail("FILE_BINDING_MISSING", path)
    result = {
        "path": path,
        "git_mode": record["git_mode"],
        "git_object_id": record["git_object_id"],
        "bytes": record["bytes"],
        "sha256": record["sha256"],
    }
    if role is not None:
        result["role"] = role
    return result


def changed_paths(repo: Path, parent: str, commit: str) -> dict[str, str]:
    raw = git(
        repo,
        "diff-tree",
        "--no-commit-id",
        "--name-status",
        "-r",
        "--no-renames",
        "-z",
        parent,
        commit,
    )
    fields = raw.split(b"\x00")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        fail("DIFF_FORMAT")
    result: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        try:
            status = fields[index].decode("ascii")
            path = fields[index + 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise InventoryError("DIFF_ENCODING") from error
        if status not in {"A", "M", "D"} or not valid_path(path) or path in result:
            fail("DIFF_RECORD", path)
        result[path] = status
    return dict(sorted(result.items()))


def prior_review_paths(
    ledger_payload: bytes, overlay_payload: bytes
) -> tuple[dict[str, str], dict[str, str]]:
    try:
        text = ledger_payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InventoryError("PRIOR_LEDGER_UTF8") from error
    reader = csv.DictReader(io.StringIO(text), strict=True)
    if reader.fieldnames is None or len(reader.fieldnames) != len(
        set(reader.fieldnames)
    ):
        fail("PRIOR_LEDGER_HEADER")
    ledger: dict[str, str] = {}
    for row in reader:
        path = row.get("path")
        digest = row.get("sha256")
        if (
            not isinstance(path, str)
            or not valid_path(path)
            or not isinstance(digest, str)
        ):
            fail("PRIOR_LEDGER_ROW")
        if path in ledger:
            fail("PRIOR_LEDGER_DUPLICATE", path)
        ledger[path] = digest
    overlay_value = strict_json(overlay_payload, label="prior-review-overlay")
    entries = overlay_value.get("entries") if isinstance(overlay_value, dict) else None
    if not isinstance(entries, list):
        fail("PRIOR_OVERLAY_SHAPE")
    overlay: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            fail("PRIOR_OVERLAY_ENTRY")
        path = entry.get("path")
        digest = entry.get("sha256")
        if (
            not isinstance(path, str)
            or not valid_path(path)
            or not isinstance(digest, str)
            or path in overlay
        ):
            fail("PRIOR_OVERLAY_ENTRY")
        overlay[path] = digest
    return ledger, overlay


def build_review_overlay(
    repo: Path,
    freeze_commit: str,
    freeze_tree: str,
    records: Sequence[dict[str, Any]],
    blobs: Mapping[str, bytes],
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    by_path = {item["path"]: item for item in records}
    prior_paths = [
        "audit/generated/FILE_REVIEW_LEDGER.csv",
        "audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json",
        (
            "release/0.9.0/current-head/tasks/ch-t002/e0002/evidence/"
            "file-review-packet-manifest.json"
        ),
        "release/0.9.0/current-head/tasks/ch-t002/e0002/qualification.json",
        "release/0.9.0/current-head/tasks/ch-t002/e0002/activation.json",
    ]
    prior_artifacts = [
        file_binding(path, by_path, role="PRIOR_REVIEW_OR_LIFECYCLE_EVIDENCE")
        for path in prior_paths
    ]
    ledger_paths, overlay_paths = prior_review_paths(
        blobs[prior_paths[0]], blobs[prior_paths[1]]
    )
    freeze_delta = changed_paths(
        repo, PRIOR_LIFECYCLE["activation_commit"], freeze_commit
    )
    expected_freeze_delta = {
        "release/0.9.0/current-head/closures/task-verifier-registry.json": "M",
        "release/0.9.0/current-head/tasks/ch-t003/e0001/freeze.json": "A",
        "tools/release/tasks/ch-t003/e0001/test_verify.py": "A",
        "tools/release/tasks/ch-t003/e0001/verify.py": "A",
    }
    if freeze_delta != expected_freeze_delta:
        fail("FREEZE_DELTA", repr(freeze_delta))
    freeze_records: list[dict[str, Any]] = []
    for record in records:
        path = record["path"]
        if path in freeze_delta:
            basis = "CH_T003_SIGNED_FREEZE_PROTOCOL"
        elif ledger_paths.get(path) == record["sha256"]:
            basis = "CH_T001_BASE_REVIEW_LEDGER_EXACT_CONTENT"
        elif overlay_paths.get(path) == record["sha256"]:
            basis = "CH_T002_REVIEW_OVERLAY_EXACT_CONTENT"
        else:
            basis = "PRIOR_SIGNED_ACTIVATION_TREE"
        freeze_records.append(
            {
                "path": path,
                "git_mode": record["git_mode"],
                "git_object_id": record["git_object_id"],
                "bytes": record["bytes"],
                "sha256": record["sha256"],
                "source_review_basis": basis,
                "assigned_review": "CH-T003-C-INDEPENDENT-QUALIFICATION",
                "review_status": "C_REVIEW_REQUIRED",
            }
        )
    candidate_records = [
        {
            "path": item["path"],
            "change": item["change"],
            "binding_kind": item["binding_kind"],
            "sha256": item["sha256"],
            "bytes": item["bytes"],
            "assigned_review": "CH-T003-C-INDEPENDENT-QUALIFICATION",
            "review_status": "C_REVIEW_REQUIRED",
        }
        for item in candidate["records"]
    ]
    freeze_paths = [item["path"] for item in freeze_records]
    candidate_paths = [item["path"] for item in candidate_records]
    if (
        len(freeze_records) != 426
        or len(candidate_records) != 9
        or len(set(freeze_paths)) != len(freeze_paths)
        or len(set(candidate_paths)) != len(candidate_paths)
        or set(candidate_paths) & set(freeze_paths) != {CLAIM_LEDGER_PATH}
    ):
        fail("REVIEW_OVERLAY_PARTITION")
    partition = {
        "freeze_commit": freeze_commit,
        "freeze_tree": freeze_tree,
        "freeze_count": len(freeze_records),
        "freeze_paths_sha256": sha256(canonical_json(freeze_paths)),
        "candidate_count": len(candidate_records),
        "candidate_added": 8,
        "candidate_modified": 1,
        "candidate_paths_sha256": sha256(canonical_json(candidate_paths)),
        "expected_implementation_count": 434,
        "disjoint_additions": True,
        "added_paths": sorted(
            set(candidate_paths) - {CLAIM_LEDGER_PATH} - set(freeze_paths)
        ),
    }
    return {
        "schema_version": "1.0.0",
        "schema_id": "haldir.ch-t003.file-review-overlay.v1",
        "task_id": TASK_ID,
        "release_target": RELEASE_TARGET,
        "author": AUTHOR,
        "persistent_identifier": None,
        "source": {
            "freeze_commit": freeze_commit,
            "freeze_tree": freeze_tree,
            "prior_activation_commit": PRIOR_LIFECYCLE["activation_commit"],
        },
        "coverage_policy": {
            "unit": "EXACT_REGULAR_GIT_BLOB_PATH_AND_CONTENT",
            "freeze_coverage": "EVERY_F_BLOB",
            "candidate_coverage": "EXACT_I_DIFF_PLAN",
            "qualification_timing": "NO_C_REVIEW_IS_CLAIMED_IN_I",
            "named_human_review_claimed": False,
        },
        "prior_artifacts": prior_artifacts,
        "freeze_records": freeze_records,
        "candidate_records": candidate_records,
        "partition": partition,
        "counts": {
            "freeze_records": len(freeze_records),
            "candidate_records": len(candidate_records),
            "implementation_records": 434,
            "prior_exact_content_bindings": sum(
                item["source_review_basis"].endswith("EXACT_CONTENT")
                for item in freeze_records
            ),
            "freeze_protocol_records": sum(
                item["source_review_basis"] == "CH_T003_SIGNED_FREEZE_PROTOCOL"
                for item in freeze_records
            ),
            "c_review_pending": len(freeze_records) + len(candidate_records),
        },
        "digests": {
            "prior_artifacts_sha256": sha256(canonical_json(prior_artifacts)),
            "freeze_records_sha256": sha256(canonical_json(freeze_records)),
            "candidate_records_sha256": sha256(canonical_json(candidate_records)),
            "partition_sha256": sha256(canonical_json(partition)),
        },
        "result": "PASS",
    }


GITHUB_API_VERSION = "2022-11-28"
GITHUB_ACCEPT = "application/vnd.github+json"
SENSITIVE_RAW_BODY_ENDPOINTS = {
    "autolinks",
    "deploy_keys",
    "hooks",
    "secrets",
    "variables",
}
GITHUB_ENDPOINTS = (
    {
        "id": "repository",
        "endpoint": f"/repos/{REPOSITORY}",
        "paginated": False,
        "allowed_statuses": (200,),
    },
    {
        "id": "topics",
        "endpoint": f"/repos/{REPOSITORY}/topics",
        "paginated": False,
        "allowed_statuses": (200,),
    },
    {
        "id": "community_profile",
        "endpoint": f"/repos/{REPOSITORY}/community/profile",
        "paginated": False,
        "allowed_statuses": (200,),
    },
    {
        "id": "license",
        "endpoint": f"/repos/{REPOSITORY}/license",
        "paginated": False,
        "allowed_statuses": (200,),
    },
    {
        "id": "languages",
        "endpoint": f"/repos/{REPOSITORY}/languages",
        "paginated": False,
        "allowed_statuses": (200,),
    },
    {
        "id": "contributors",
        "endpoint": f"/repos/{REPOSITORY}/contributors?per_page=100&anon=1",
        "paginated": True,
        "allowed_statuses": (200,),
    },
    {
        "id": "branches",
        "endpoint": f"/repos/{REPOSITORY}/branches?per_page=100",
        "paginated": True,
        "allowed_statuses": (200,),
    },
    {
        "id": "main_protection",
        "endpoint": f"/repos/{REPOSITORY}/branches/main/protection",
        "paginated": False,
        "allowed_statuses": (200, 404),
    },
    {
        "id": "rulesets",
        "endpoint": f"/repos/{REPOSITORY}/rulesets?per_page=100",
        "paginated": True,
        "allowed_statuses": (200, 404),
    },
    {
        "id": "tags",
        "endpoint": f"/repos/{REPOSITORY}/tags?per_page=100",
        "paginated": True,
        "allowed_statuses": (200,),
    },
    {
        "id": "releases",
        "endpoint": f"/repos/{REPOSITORY}/releases?per_page=100",
        "paginated": True,
        "allowed_statuses": (200,),
    },
    {
        "id": "workflows",
        "endpoint": f"/repos/{REPOSITORY}/actions/workflows?per_page=100",
        "paginated": True,
        "allowed_statuses": (200,),
    },
    {
        "id": "actions_permissions",
        "endpoint": f"/repos/{REPOSITORY}/actions/permissions",
        "paginated": False,
        "allowed_statuses": (200,),
    },
    {
        "id": "workflow_token_permissions",
        "endpoint": f"/repos/{REPOSITORY}/actions/permissions/workflow",
        "paginated": False,
        "allowed_statuses": (200,),
    },
    {
        "id": "environments",
        "endpoint": f"/repos/{REPOSITORY}/environments?per_page=100",
        "paginated": True,
        "allowed_statuses": (200, 404),
    },
    {
        "id": "variables",
        "endpoint": f"/repos/{REPOSITORY}/actions/variables?per_page=100",
        "paginated": True,
        "allowed_statuses": (200, 404),
    },
    {
        "id": "secrets",
        "endpoint": f"/repos/{REPOSITORY}/actions/secrets?per_page=100",
        "paginated": True,
        "allowed_statuses": (200, 404),
        "sensitive": "SECRET_NAMES_ONLY",
    },
    {
        "id": "pages",
        "endpoint": f"/repos/{REPOSITORY}/pages",
        "paginated": False,
        "allowed_statuses": (200, 404),
    },
    {
        "id": "vulnerability_alerts",
        "endpoint": f"/repos/{REPOSITORY}/vulnerability-alerts",
        "paginated": False,
        "allowed_statuses": (204, 404),
    },
    {
        "id": "private_vulnerability_reporting",
        "endpoint": f"/repos/{REPOSITORY}/private-vulnerability-reporting",
        "paginated": False,
        "allowed_statuses": (200, 404),
    },
    {
        "id": "code_scanning_default_setup",
        "endpoint": f"/repos/{REPOSITORY}/code-scanning/default-setup",
        "paginated": False,
        "allowed_statuses": (200, 404),
    },
    {
        "id": "hooks",
        "endpoint": f"/repos/{REPOSITORY}/hooks?per_page=100",
        "paginated": True,
        "allowed_statuses": (200,),
        "sensitive": "HOOK_CONFIG_VALUES",
    },
    {
        "id": "deploy_keys",
        "endpoint": f"/repos/{REPOSITORY}/keys?per_page=100",
        "paginated": True,
        "allowed_statuses": (200,),
        "sensitive": "PUBLIC_KEY_MATERIAL",
    },
    {
        "id": "autolinks",
        "endpoint": f"/repos/{REPOSITORY}/autolinks?per_page=100",
        "paginated": True,
        "allowed_statuses": (200,),
    },
    {
        "id": "interaction_limits",
        "endpoint": f"/repos/{REPOSITORY}/interaction-limits",
        "paginated": False,
        "allowed_statuses": (200, 204, 404),
    },
)


def github_token(repo: Path) -> str:
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    gh = shutil.which("gh")
    if gh is None:
        fail("GITHUB_AUTH_UNAVAILABLE")
    completed = command(
        [gh, "auth", "token", "--hostname", "github.com"],
        cwd=repo,
        maximum=16_384,
        allow_stderr=True,
    )
    try:
        value = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise InventoryError("GITHUB_TOKEN_ENCODING") from error
    if not value or any(character.isspace() for character in value):
        fail("GITHUB_TOKEN_INVALID")
    return value


def github_api_url(
    url: str,
    *,
    error_code: str = "GITHUB_URL_SCOPE",
) -> urllib.parse.ParseResult:
    if not isinstance(url, str) or any(ord(character) < 32 for character in url):
        fail(error_code, repr(url))
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as error:
        raise InventoryError(f"{error_code}:{url}") from error
    repository_path = f"/repos/{REPOSITORY}"
    path_segments = parsed.path.split("/")
    if (
        parsed.scheme != "https"
        or parsed.netloc != "api.github.com"
        or (
            parsed.path != repository_path
            and not parsed.path.startswith(repository_path + "/")
        )
        or any(segment in {"", ".", ".."} for segment in path_segments[1:])
        or "%" in parsed.path
        or "\\" in parsed.path
        or parsed.params
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        fail(error_code, url)
    return parsed


def github_capture_endpoint(
    url: str,
    specification: Mapping[str, Any],
    page: int,
) -> str:
    parsed = github_api_url(url, error_code="GITHUB_CAPTURE_URL")
    base = urllib.parse.urlparse("https://api.github.com" + specification["endpoint"])
    try:
        base_query = urllib.parse.parse_qsl(
            base.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
        actual_query = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError as error:
        raise InventoryError("GITHUB_CAPTURE_QUERY") from error
    expected_query = base_query + ([] if page == 1 else [("page", str(page))])
    if (
        parsed.path != base.path
        or len({key for key, _value in actual_query}) != len(actual_query)
        or actual_query != expected_query
    ):
        fail("GITHUB_CAPTURE_SEQUENCE", specification["id"])
    query = urllib.parse.urlencode(expected_query)
    return parsed.path + (f"?{query}" if query else "")


class RejectGithubRedirect(urllib.request.HTTPRedirectHandler):
    def reject(
        self,
        request: urllib.request.Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
    ) -> None:
        del request, response, message, headers
        fail("GITHUB_REDIRECT", str(code))

    http_error_301 = reject
    http_error_302 = reject
    http_error_303 = reject
    http_error_307 = reject
    http_error_308 = reject


def live_github_fetch(token: str) -> Callable[[str], tuple[int, dict[str, str], bytes]]:
    if not token or any(character.isspace() for character in token):
        fail("GITHUB_TOKEN_INVALID")
    tls_context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=tls_context),
        RejectGithubRedirect(),
    )

    def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
        github_api_url(url)
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": GITHUB_ACCEPT,
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "haldir-ch-t003-inventory",
            },
        )
        try:
            with opener.open(request, timeout=30) as response:
                body = response.read(MAX_HTTP_BODY_BYTES + 1)
                status = response.status
                headers = {
                    key.casefold(): value for key, value in response.headers.items()
                }
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400:
                raise InventoryError(f"GITHUB_REDIRECT:{error.code}") from error
            body = error.read(MAX_HTTP_BODY_BYTES + 1)
            status = error.code
            headers = {key.casefold(): value for key, value in error.headers.items()}
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise InventoryError("GITHUB_NETWORK") from error
        if 300 <= status < 400:
            fail("GITHUB_REDIRECT", str(status))
        if len(body) > MAX_HTTP_BODY_BYTES:
            fail("GITHUB_BODY_LIMIT")
        return status, headers, body

    return fetch


def github_links(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    result: dict[str, str] = {}
    for part in value.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*', part)
        if match is None or match.group(2) in result:
            fail("GITHUB_LINK_HEADER")
        result[match.group(2)] = match.group(1)
    return result


def redact_github_document(endpoint_id: str, document: Any) -> tuple[Any, list[str]]:
    redactions: list[str] = []
    if endpoint_id == "hooks":
        if not isinstance(document, list):
            fail("GITHUB_HOOK_SHAPE")
        sanitized: list[Any] = []
        for index, item in enumerate(document):
            if not isinstance(item, dict):
                fail("GITHUB_HOOK_SHAPE")
            sanitized.append({"present": True})
            redactions.append(f"/{index}/*")
        return sanitized, redactions
    if endpoint_id == "deploy_keys":
        if not isinstance(document, list):
            fail("GITHUB_DEPLOY_KEY_SHAPE")
        sanitized = []
        for index, item in enumerate(document):
            if not isinstance(item, dict):
                fail("GITHUB_DEPLOY_KEY_SHAPE")
            sanitized.append({"present": True})
            redactions.append(f"/{index}/*")
        return sanitized, redactions
    if endpoint_id == "autolinks":
        if not isinstance(document, list):
            fail("GITHUB_AUTOLINK_SHAPE")
        for index, item in enumerate(document):
            if not isinstance(item, dict):
                fail("GITHUB_AUTOLINK_SHAPE")
            redactions.append(f"/{index}/*")
        return [{"present": True} for _item in document], redactions
    if endpoint_id == "variables":
        if (
            not isinstance(document, dict)
            or type(document.get("total_count")) is not int
            or document["total_count"] < 0
        ):
            fail("GITHUB_VARIABLES_SHAPE")
        variables = document.get("variables", [])
        if not isinstance(variables, list):
            fail("GITHUB_VARIABLES_SHAPE")
        safe = []
        for index, item in enumerate(variables):
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("name"), str)
                or not item["name"]
                or not isinstance(item.get("value"), str)
                or any(
                    key in item and not isinstance(item[key], str)
                    for key in ("created_at", "updated_at")
                )
            ):
                fail("GITHUB_VARIABLE_ENTRY_SHAPE")
            safe.append(
                {
                    key: item.get(key)
                    for key in ("name", "created_at", "updated_at")
                    if key in item
                }
            )
            redactions.append(f"/variables/{index}/value")
        return {
            "total_count": document.get("total_count"),
            "variables": safe,
        }, redactions
    if endpoint_id == "secrets":
        if (
            not isinstance(document, dict)
            or type(document.get("total_count")) is not int
            or document["total_count"] < 0
        ):
            fail("GITHUB_SECRETS_SHAPE")
        secrets = document.get("secrets", [])
        if not isinstance(secrets, list):
            fail("GITHUB_SECRETS_SHAPE")
        safe = []
        for index, item in enumerate(secrets):
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("name"), str)
                or not item["name"]
                or any(
                    key in item and not isinstance(item[key], str)
                    for key in ("created_at", "updated_at")
                )
            ):
                fail("GITHUB_SECRET_ENTRY_SHAPE")
            safe.append(
                {
                    key: item.get(key)
                    for key in ("name", "created_at", "updated_at")
                    if key in item
                }
            )
            redactions.append(f"/secrets/{index}/values-not-returned-by-api")
        return {"total_count": document.get("total_count"), "secrets": safe}, redactions
    return document, redactions


def disposition_for_status(endpoint_id: str, status: int) -> str:
    if status in {200, 204}:
        if status == 204:
            return "ENABLED_OR_EMPTY_NO_CONTENT"
        return "OBSERVED"
    if status == 404:
        return "ABSENT_DISABLED_OR_NOT_CONFIGURED"
    if status in {401, 403}:
        return "PERMISSION_DENIED"
    return "UNEXPECTED_HTTP_STATUS"


def capture_github(
    fetch: Callable[[str], tuple[int, dict[str, str], bytes]],
    *,
    captured_at_utc: str,
) -> dict[str, Any]:
    captures: list[dict[str, Any]] = []
    endpoint_summary: list[dict[str, Any]] = []
    total_bytes = 0
    combined: dict[str, list[Any]] = {}
    for specification in GITHUB_ENDPOINTS:
        endpoint_id = specification["id"]
        endpoint = specification["endpoint"]
        url = "https://api.github.com" + endpoint
        page = 1
        documents: list[Any] = []
        statuses: list[int] = []
        while True:
            if page > MAX_GITHUB_PAGES:
                fail("GITHUB_PAGE_LIMIT", endpoint_id)
            status, headers, body = fetch(url)
            total_bytes += len(body)
            if total_bytes > MAX_HTTP_TOTAL_BYTES:
                fail("GITHUB_TOTAL_BODY_LIMIT")
            if status not in specification["allowed_statuses"]:
                fail("GITHUB_HTTP_STATUS", f"{endpoint_id}:{status}")
            if body:
                document = strict_json(
                    body,
                    label=f"github:{endpoint_id}:{page}",
                    maximum=MAX_HTTP_BODY_BYTES,
                )
            else:
                document = None
            if endpoint_id in SENSITIVE_RAW_BODY_ENDPOINTS and status != 200:
                sanitized, redactions = None, []
            else:
                sanitized, redactions = redact_github_document(endpoint_id, document)
            retained_document = canonical_json(sanitized)
            link = headers.get("link")
            retain_raw_body = endpoint_id not in SENSITIVE_RAW_BODY_ENDPOINTS
            capture_endpoint = github_capture_endpoint(url, specification, page)
            captures.append(
                {
                    "id": f"{endpoint_id}#page-{page:04d}",
                    "endpoint": capture_endpoint,
                    "page": page,
                    "method": "GET",
                    "accept": GITHUB_ACCEPT,
                    "api_version": GITHUB_API_VERSION,
                    "http_status": status,
                    "etag": headers.get("etag") if retain_raw_body else None,
                    "link": link if retain_raw_body else None,
                    "bytes": len(body) if retain_raw_body else None,
                    "sha256": sha256(body) if retain_raw_body else None,
                    "document_bytes": len(retained_document),
                    "document_sha256": sha256(retained_document),
                    "disposition": disposition_for_status(endpoint_id, status),
                    "redaction": redactions,
                    "document": sanitized,
                }
            )
            statuses.append(status)
            documents.append(sanitized if status == 200 else None)
            links = github_links(link)
            next_url = links.get("next")
            if not specification["paginated"] and next_url is not None:
                fail("GITHUB_UNEXPECTED_PAGINATION", endpoint_id)
            if next_url is None or status == 404:
                break
            github_api_url(next_url, error_code="GITHUB_NEXT_URL")
            url = next_url
            page += 1
        combined[endpoint_id] = documents
        endpoint_summary.append(
            {
                "id": endpoint_id,
                "endpoint": endpoint,
                "pages": len(documents),
                "http_statuses": statuses,
                "disposition": disposition_for_status(endpoint_id, statuses[-1]),
                "complete": True,
            }
        )
    normalized = normalize_github(combined, endpoint_summary)
    return {
        "schema_version": "1.0.0",
        "schema_id": "haldir.ch-t003.github-metadata.v1",
        "task_id": TASK_ID,
        "release_target": RELEASE_TARGET,
        "author": AUTHOR,
        "persistent_identifier": None,
        "captured_at_utc": captured_at_utc,
        "repository": {
            "owner": "sepahead",
            "name": "haldir",
            "full_name": REPOSITORY,
            "default_branch": "main",
        },
        "request_policy": {
            "method": "GET",
            "accept": GITHUB_ACCEPT,
            "api_version": GITHUB_API_VERSION,
            "authentication": "BEARER_TOKEN_USED_NOT_RETAINED",
            "pagination": "FOLLOW_REL_NEXT_TO_CLOSURE",
            "per_page": 100,
            "raw_body": "OMITTED_FOR_SENSITIVE_ENDPOINTS_OTHERWISE_DIGEST_AND_SIZE",
            "retained_document": "CANONICAL_JSON_DIGEST_AND_SIZE",
            "sensitive_values": "FIELD_LEVEL_REDACTION",
        },
        "captures": captures,
        "endpoint_summary": endpoint_summary,
        "normalized": normalized,
        "captures_sha256": sha256(canonical_json(captures)),
        "result": "PASS",
    }


def github_documents(combined: Mapping[str, list[Any]], endpoint_id: str) -> list[Any]:
    pages = combined[endpoint_id]
    return [document for document in pages if document is not None]


def github_list(
    combined: Mapping[str, list[Any]],
    endpoint_id: str,
    *,
    collection_key: str | None = None,
) -> list[Any]:
    result: list[Any] = []
    for document in github_documents(combined, endpoint_id):
        if collection_key is not None:
            if not isinstance(document, dict) or not isinstance(
                document.get(collection_key), list
            ):
                fail("GITHUB_COLLECTION_SHAPE", endpoint_id)
            result.extend(document[collection_key])
        else:
            if not isinstance(document, list):
                fail("GITHUB_LIST_SHAPE", endpoint_id)
            result.extend(document)
    return result


def github_single(combined: Mapping[str, list[Any]], endpoint_id: str) -> Any:
    documents = github_documents(combined, endpoint_id)
    if len(documents) > 1:
        fail("GITHUB_SINGLE_SHAPE", endpoint_id)
    return documents[0] if documents else None


def normalize_github(
    combined: Mapping[str, list[Any]], endpoint_summary: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    repository = github_single(combined, "repository")
    topics = github_single(combined, "topics")
    community = github_single(combined, "community_profile")
    license_record = github_single(combined, "license")
    languages = github_single(combined, "languages")
    if not all(
        isinstance(item, dict)
        for item in (repository, topics, community, license_record, languages)
    ):
        fail("GITHUB_CORE_SHAPE")
    owner = repository.get("owner")
    license_value = license_record.get("license")
    normalized_repository = {
        key: repository.get(key)
        for key in (
            "node_id",
            "name",
            "full_name",
            "description",
            "homepage",
            "default_branch",
            "private",
            "visibility",
            "archived",
            "disabled",
            "fork",
            "is_template",
            "language",
            "size",
            "open_issues_count",
            "allow_forking",
            "web_commit_signoff_required",
        )
    }
    normalized_repository["owner"] = (
        owner.get("login") if isinstance(owner, dict) else None
    )
    branches = github_list(combined, "branches")
    contributors = github_list(combined, "contributors")
    rulesets = github_list(combined, "rulesets")
    tags = github_list(combined, "tags")
    releases = github_list(combined, "releases")
    workflows = github_list(combined, "workflows", collection_key="workflows")
    environments = github_list(combined, "environments", collection_key="environments")
    variables = github_list(combined, "variables", collection_key="variables")
    secrets = github_list(combined, "secrets", collection_key="secrets")
    hooks = github_list(combined, "hooks")
    deploy_keys = github_list(combined, "deploy_keys")
    autolinks = github_list(combined, "autolinks")
    if tags or releases:
        fail("GITHUB_PUBLICATION_NOT_EMPTY")
    if (
        normalized_repository["owner"] != "sepahead"
        or normalized_repository["name"] != "haldir"
        or normalized_repository["full_name"] != REPOSITORY
        or normalized_repository["default_branch"] != "main"
        or normalized_repository["private"] is not False
        or normalized_repository["archived"] is not False
        or normalized_repository["disabled"] is not False
    ):
        fail("GITHUB_REPOSITORY_IDENTITY")
    feature_fields = (
        "has_issues",
        "has_projects",
        "has_wiki",
        "has_pages",
        "has_discussions",
        "allow_squash_merge",
        "allow_merge_commit",
        "allow_rebase_merge",
        "allow_auto_merge",
        "delete_branch_on_merge",
        "use_squash_pr_title_as_default",
        "squash_merge_commit_title",
        "squash_merge_commit_message",
        "merge_commit_title",
        "merge_commit_message",
    )
    statuses = {item["id"]: item["disposition"] for item in endpoint_summary}
    default_branch_head = next(
        (
            (item.get("commit") or {}).get("sha")
            for item in branches
            if isinstance(item, dict)
            and item.get("name") == normalized_repository["default_branch"]
            and isinstance(item.get("commit"), dict)
        ),
        None,
    )
    normalized = {
        "owner": normalized_repository["owner"],
        "default_branch": normalized_repository["default_branch"],
        "default_branch_head": default_branch_head,
        "private": normalized_repository["private"],
        "archived": normalized_repository["archived"],
        "disabled": normalized_repository["disabled"],
        "tag_count": len(tags),
        "release_count": len(releases),
        "repository": normalized_repository,
        "community": {
            "health_percentage": community.get("health_percentage"),
            "files": community.get("files"),
        },
        "topics": sorted(topics.get("names", [])),
        "license": {
            "spdx_id": license_value.get("spdx_id")
            if isinstance(license_value, dict)
            else None,
            "name": license_value.get("name")
            if isinstance(license_value, dict)
            else None,
        },
        "languages": dict(sorted(languages.items())),
        "contributors": [
            {
                "login": item.get("login"),
                "id": item.get("id"),
                "type": item.get("type"),
                "contributions": item.get("contributions"),
                "anonymous": item.get("type") == "Anonymous",
            }
            for item in contributors
            if isinstance(item, dict)
        ],
        "branches": [
            {
                "name": item.get("name"),
                "protected": item.get("protected"),
                "commit_sha": (item.get("commit") or {}).get("sha")
                if isinstance(item.get("commit"), dict)
                else None,
            }
            for item in branches
            if isinstance(item, dict)
        ],
        "protection": {
            "main": github_single(combined, "main_protection"),
            "main_disposition": statuses["main_protection"],
        },
        "rulesets": rulesets,
        "publication": {
            "tag_count": len(tags),
            "release_count": len(releases),
            "tags": tags,
            "releases": releases,
        },
        "workflows": [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "path": item.get("path"),
                "state": item.get("state"),
            }
            for item in workflows
            if isinstance(item, dict)
        ],
        "actions_permissions": {
            "repository": github_single(combined, "actions_permissions"),
            "workflow_token": github_single(combined, "workflow_token_permissions"),
        },
        "environments": [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "protection_rules": item.get("protection_rules"),
                "deployment_branch_policy": item.get("deployment_branch_policy"),
            }
            for item in environments
            if isinstance(item, dict)
        ],
        "variable_names": sorted(
            item.get("name") for item in variables if isinstance(item, dict)
        ),
        "secret_names": sorted(
            item.get("name") for item in secrets if isinstance(item, dict)
        ),
        "pages": {
            "disposition": statuses["pages"],
            "settings": github_single(combined, "pages"),
        },
        "security": {
            "repository_security_and_analysis": repository.get("security_and_analysis"),
            "vulnerability_alerts": statuses["vulnerability_alerts"],
            "private_vulnerability_reporting": github_single(
                combined, "private_vulnerability_reporting"
            ),
            "private_vulnerability_reporting_disposition": statuses[
                "private_vulnerability_reporting"
            ],
            "code_scanning_default_setup": github_single(
                combined, "code_scanning_default_setup"
            ),
            "code_scanning_default_setup_disposition": statuses[
                "code_scanning_default_setup"
            ],
        },
        "features": {key: repository.get(key) for key in feature_fields},
        "hooks": {"count": len(hooks), "present": bool(hooks)},
        "deploy_keys": {"count": len(deploy_keys), "present": bool(deploy_keys)},
        "autolinks": {"count": len(autolinks), "present": bool(autolinks)},
        "interaction_limits": {
            "disposition": statuses["interaction_limits"],
            "settings": github_single(combined, "interaction_limits"),
        },
        "completeness": {
            "expected_endpoint_ids": [item["id"] for item in GITHUB_ENDPOINTS],
            "captured_endpoint_ids": [item["id"] for item in endpoint_summary],
            "all_complete": all(item["complete"] for item in endpoint_summary),
            "permission_denied": [
                item["id"]
                for item in endpoint_summary
                if item["disposition"] == "PERMISSION_DENIED"
            ],
        },
    }
    if (
        normalized["completeness"]["expected_endpoint_ids"]
        != normalized["completeness"]["captured_endpoint_ids"]
        or not normalized["completeness"]["all_complete"]
        or normalized["completeness"]["permission_denied"]
    ):
        fail("GITHUB_CAPTURE_INCOMPLETE")
    return normalized


def scan_language_text(
    payload: bytes,
    *,
    pattern: re.Pattern[str],
    scope: str,
    path: str | None,
    member: str | None,
    endpoint: str | None,
) -> list[dict[str, Any]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return []
    hits: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        encoded_line = line.encode("utf-8")
        ids = sorted(set(CLAIM_ID_PATTERN.findall(line)))
        for match in pattern.finditer(line):
            value = match.group(0)
            hits.append(
                {
                    "scope": scope,
                    "path": path,
                    "member": member,
                    "endpoint": endpoint,
                    "line": line_number,
                    "column": match.start() + 1,
                    "match": value,
                    "normalized_term": re.sub(r"[-\s]+", " ", value.casefold()),
                    "claim_ids": ids,
                    "line_sha256": sha256(encoded_line),
                }
            )
            if len(hits) > MAX_LANGUAGE_HITS:
                fail("CLAIM_LANGUAGE_HIT_LIMIT")
    return hits


def build_claim_language(
    freeze_commit: str,
    freeze_tree: str,
    records: Sequence[dict[str, Any]],
    blobs: Mapping[str, bytes],
    archives: Sequence[dict[str, Any]],
    expanded_contents: Mapping[tuple[str, str], bytes],
    cli: Mapping[str, Any],
    github: Mapping[str, Any],
    candidate_ledger: bytes,
) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []
    for record in records:
        path = record["path"]
        payload = blobs[path]
        kind = content_kind(path, payload)
        sources.append(
            {
                "scope": "TRACKED",
                "path": path,
                "member": None,
                "endpoint": None,
                "sha256": sha256(payload),
                "bytes": len(payload),
                "content_kind": kind,
            }
        )
        if path.casefold().endswith((".md", ".rst", ".txt")):
            hits.extend(
                scan_language_text(
                    payload,
                    pattern=BASELINE_PATTERN,
                    scope="HANDOFF_BASELINE_TRACKED_TEXT",
                    path=path,
                    member=None,
                    endpoint=None,
                )
            )
        if kind == "UTF8" and path != CLAIM_LEDGER_PATH:
            hits.extend(
                scan_language_text(
                    payload,
                    pattern=EXTENDED_PATTERN,
                    scope="EXTENDED_TRACKED_UTF8",
                    path=path,
                    member=None,
                    endpoint=None,
                )
            )
    sources.append(
        {
            "scope": "CANDIDATE_CLAIM_LEDGER",
            "path": CLAIM_LEDGER_PATH,
            "member": None,
            "endpoint": None,
            "sha256": sha256(candidate_ledger),
            "bytes": len(candidate_ledger),
            "content_kind": "UTF8",
        }
    )
    hits.extend(
        scan_language_text(
            candidate_ledger,
            pattern=EXTENDED_PATTERN,
            scope="EXTENDED_CANDIDATE_CLAIM_LEDGER_UTF8",
            path=CLAIM_LEDGER_PATH,
            member=None,
            endpoint=None,
        )
    )
    for archive in archives:
        for member_record in archive["members"]:
            key = (archive["path"], member_record["name"])
            payload = expanded_contents[key]
            sources.append(
                {
                    "scope": "ARCHIVE_MEMBER",
                    "path": archive["path"],
                    "member": member_record["name"],
                    "endpoint": None,
                    "sha256": member_record["sha256"],
                    "bytes": member_record["bytes"],
                    "content_kind": member_record["content_kind"],
                }
            )
            if member_record["content_kind"] == "UTF8":
                hits.extend(
                    scan_language_text(
                        payload,
                        pattern=EXTENDED_PATTERN,
                        scope="EXTENDED_ARCHIVE_MEMBER_UTF8",
                        path=archive["path"],
                        member=member_record["name"],
                        endpoint=None,
                    )
                )
    for observation in cli["runtime_observations"]:
        for stream in ("stdout", "stderr"):
            payload = observation[stream].encode("utf-8")
            channel = f"{observation['scenario']}:{stream}"
            sources.append(
                {
                    "scope": "CLI_RUNTIME",
                    "path": None,
                    "member": None,
                    "endpoint": channel,
                    "sha256": sha256(payload),
                    "bytes": len(payload),
                    "content_kind": "UTF8",
                }
            )
            hits.extend(
                scan_language_text(
                    payload,
                    pattern=EXTENDED_PATTERN,
                    scope="EXTENDED_CLI_RUNTIME_UTF8",
                    path=None,
                    member=None,
                    endpoint=channel,
                )
            )
    description = github["normalized"]["repository"].get("description")
    description_payload = (
        description.encode("utf-8") if isinstance(description, str) else b""
    )
    sources.append(
        {
            "scope": "GITHUB_DESCRIPTION",
            "path": None,
            "member": None,
            "endpoint": f"https://github.com/{REPOSITORY}",
            "sha256": sha256(description_payload),
            "bytes": len(description_payload),
            "content_kind": "UTF8" if description_payload else "ABSENT",
        }
    )
    if description_payload:
        hits.extend(
            scan_language_text(
                description_payload,
                pattern=EXTENDED_PATTERN,
                scope="EXTENDED_GITHUB_DESCRIPTION_UTF8",
                path=None,
                member=None,
                endpoint=f"https://github.com/{REPOSITORY}",
            )
        )
    sources.sort(
        key=lambda item: (
            item["scope"],
            item["path"] or "",
            item["member"] or "",
            item["endpoint"] or "",
        )
    )
    hits.sort(
        key=lambda item: (
            item["scope"],
            item["path"] or "",
            item["member"] or "",
            item["endpoint"] or "",
            item["line"],
            item["column"],
            item["match"],
        )
    )
    baseline_hits = [
        item for item in hits if item["scope"] == "HANDOFF_BASELINE_TRACKED_TEXT"
    ]
    baseline_lines = {(item["path"], item["line"]) for item in baseline_hits}
    baseline_paths = {item["path"] for item in baseline_hits}
    if (
        len(baseline_hits) != 1_379
        or len(baseline_lines) != 1_181
        or len(
            [
                item
                for item in sources
                if item["scope"] == "TRACKED"
                and item["path"].casefold().endswith((".md", ".rst", ".txt"))
            ]
        )
        != 49
        or len(baseline_paths) > 49
    ):
        fail(
            "CLAIM_LANGUAGE_BASELINE_INVARIANT",
            f"{len(baseline_hits)}:{len(baseline_lines)}:{len(baseline_paths)}",
        )
    if len(hits) > MAX_LANGUAGE_HITS:
        fail("CLAIM_LANGUAGE_HIT_LIMIT")
    tracked_digest = sha256(
        canonical_json([item for item in sources if item["scope"] == "TRACKED"])
    )
    archive_digest = sha256(
        canonical_json([item for item in sources if item["scope"] == "ARCHIVE_MEMBER"])
    )
    cli_digest = sha256(
        canonical_json([item for item in sources if item["scope"] == "CLI_RUNTIME"])
    )
    files_or_channels = {
        (
            item["scope"],
            item["path"],
            item["member"],
            item["endpoint"],
        )
        for item in hits
    }
    return {
        "schema_version": "1.0.0",
        "schema_id": "haldir.ch-t003.claim-language.v1",
        "task_id": TASK_ID,
        "release_target": RELEASE_TARGET,
        "author": AUTHOR,
        "persistent_identifier": None,
        "source": {
            "freeze_commit": freeze_commit,
            "freeze_tree": freeze_tree,
            "records_sha256": tracked_digest,
            "archives_sha256": archive_digest,
            "cli_runtime_sha256": cli_digest,
            "github_description_sha256": sha256(description_payload),
        },
        "policy": {
            "baseline_pattern": BASELINE_PATTERN_TEXT,
            "baseline_scope": (
                "All signed-F .md/.rst/.txt blobs without candidate substitution"
            ),
            "extended_pattern": EXTENDED_PATTERN_TEXT,
            "extended_scope": [
                "ALL_UTF8_TRACKED_BLOBS",
                "CANDIDATE_I_CLAIM_LEDGER",
                "ALL_UTF8_BOUNDED_ARCHIVE_MEMBERS",
                "CRITICAL_CLI_RUNTIME_OUTPUT",
                "GITHUB_REPOSITORY_DESCRIPTION",
            ],
            "word_boundaries": True,
            "line_text_retained": False,
            "undecodable_content": "IDENTIFIED_IN_SOURCE_LIST_NOT_SILENTLY_SKIPPED",
        },
        "sources": sources,
        "hits": hits,
        "counts": {
            "sources": len(sources),
            "hits": len(hits),
            "baseline_hits": len(baseline_hits),
            "extended_hits": len(hits) - len(baseline_hits),
            "tracked_hits": sum("TRACKED" in item["scope"] for item in hits),
            "archive_hits": sum("ARCHIVE" in item["scope"] for item in hits),
            "cli_hits": sum("CLI" in item["scope"] for item in hits),
            "github_hits": sum("GITHUB" in item["scope"] for item in hits),
            "files_or_channels": len(files_or_channels),
        },
        "hits_sha256": sha256(canonical_json(hits)),
        "result": "PASS",
    }


def public_toolchain_record(toolchain: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "toolchain": toolchain["toolchain"],
        "tools": toolchain["tools"],
        "cargo_public_api": {
            key: value
            for key, value in toolchain["cargo_public_api"].items()
            if key != "path"
        },
        "cross_compiler": {
            key: value
            for key, value in toolchain["cross_compiler"].items()
            if key != "path"
        },
        "targets": toolchain["targets"],
        "rustdoc_json_format": toolchain["rustdoc_json_format"],
        "bootstrap": toolchain["bootstrap"],
    }


def build_public_inventory(
    *,
    freeze_commit: str,
    freeze_tree: str,
    object_format: str,
    signature: Mapping[str, Any],
    records: Sequence[dict[str, Any]],
    archives: Sequence[dict[str, Any]],
    toolchain: Mapping[str, Any],
    cargo: Mapping[str, Any],
    public_api: Mapping[str, Any],
    cli: Mapping[str, Any],
    ipc: Mapping[str, Any],
    schemas: Mapping[str, Any],
    documentation: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    classification_counts = dict(
        sorted(Counter(item["classification"] for item in records).items())
    )
    archive_counts = Counter(item["archive_type"] for item in archives)
    if (
        len(records) != 426
        or archive_counts != Counter({"GZIP": 30, "ZIP": 4})
        or candidate["expected_implementation_regular_blobs"] != 434
    ):
        fail("PUBLIC_PROJECT_CARDINALITY")
    cargo_inventory = {
        "toolchain": public_toolchain_record(toolchain),
        "metadata": cargo["metadata"],
        "declared_mismatch": cargo["declared_mismatch"],
        "public_api": public_api,
    }
    digests = {
        "records_sha256": sha256(canonical_json(records)),
        "archives_sha256": sha256(canonical_json(archives)),
        "cargo_sha256": sha256(canonical_json(cargo_inventory)),
        "cli_sha256": sha256(canonical_json(cli)),
        "ipc_sha256": sha256(canonical_json(ipc)),
        "schemas_sha256": sha256(canonical_json(schemas)),
        "documentation_sha256": sha256(canonical_json(documentation)),
        "candidate_implementation_sha256": sha256(canonical_json(candidate)),
    }
    return {
        "schema_version": "1.0.0",
        "schema_id": "haldir.ch-t003.public-surface-inventory.v1",
        "task_id": TASK_ID,
        "release_target": RELEASE_TARGET,
        "author": AUTHOR,
        "persistent_identifier": None,
        "source": {
            "freeze_commit": freeze_commit,
            "freeze_tree": freeze_tree,
            "object_format": object_format,
            "signature": signature,
            "regular_blob_count": len(records),
            "aggregate_blob_bytes": sum(item["bytes"] for item in records),
            "resource_limits": {
                "per_blob_bytes": MAX_BLOB_BYTES,
                "aggregate_blob_bytes": MAX_AGGREGATE_BLOB_BYTES,
                "per_archive_member_bytes": MAX_ARCHIVE_MEMBER_BYTES,
                "aggregate_archive_expanded_bytes": MAX_ARCHIVE_EXPANDED_BYTES,
                "per_output_bytes": MAX_OUTPUT_BYTES,
            },
        },
        "policy": {
            "id": "HALDIR_PUBLIC_SURFACE_COMPLETE_F_TREE_POLICY_V1",
            "scope": "ALL_REGULAR_GIT_BLOBS_AT_SIGNED_F_TREE",
            "ordering": "UTF8_PATH_ASCENDING",
            "classification_partition": sorted(ALL_CLASSIFICATIONS),
            "public_classifications": sorted(PUBLIC_CLASSIFICATIONS),
            "excluded_classifications": sorted(EXCLUDED_CLASSIFICATIONS),
            "unknown_path_or_extension": "FAIL",
            "nonregular_git_entry": "FAIL",
            "lfs_pointer": "FAIL",
            "structured_parse_error_or_duplicate_key": "FAIL",
            "compiler_api_precedence": (
                "PINNED_COMPILER_RESOLVED_ORACLE_OVERRIDES_LEXICAL_PUB_HEURISTICS"
            ),
        },
        "records": list(records),
        "archives": list(archives),
        "cargo": cargo_inventory,
        "cli": cli,
        "ipc": ipc,
        "schemas": schemas,
        "documentation": documentation,
        "candidate_implementation": candidate,
        "counts": {
            "regular_blobs": len(records),
            "aggregate_blob_bytes": sum(item["bytes"] for item in records),
            "surface_records": sum(
                item["disposition"] == "SURFACE" for item in records
            ),
            "excluded_records": sum(
                item["disposition"] == "EXCLUDED" for item in records
            ),
            "by_classification": classification_counts,
            "zip_archives": archive_counts["ZIP"],
            "gzip_archives": archive_counts["GZIP"],
            "archive_members": sum(item["member_count"] for item in archives),
            "archive_expanded_bytes": sum(item["expanded_bytes"] for item in archives),
            "candidate_paths": len(candidate["records"]),
            "expected_implementation_regular_blobs": 434,
        },
        "digests": digests,
        "result": "PASS",
    }


def generated_binding(path: str, payload: bytes, role: str) -> dict[str, Any]:
    return {
        "path": path,
        "bytes": len(payload),
        "sha256": sha256(payload),
        "role": role,
    }


def build_ledger_composition(
    *,
    freeze_commit: str,
    freeze_tree: str,
    records: Sequence[dict[str, Any]],
    candidate: Mapping[str, Any],
    overlay: Mapping[str, Any],
    sibling_payloads: Mapping[str, bytes],
) -> dict[str, Any]:
    by_path = {item["path"]: item for item in records}
    prior_paths = [
        "audit/generated/FILE_REVIEW_LEDGER.csv",
        "audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json",
        (
            "release/0.9.0/current-head/tasks/ch-t002/e0002/evidence/"
            "file-review-packet-manifest.json"
        ),
        "release/0.9.0/current-head/tasks/ch-t002/e0002/qualification.json",
        "release/0.9.0/current-head/tasks/ch-t002/e0002/activation.json",
    ]
    prior_artifacts = [
        file_binding(path, by_path, role="PRIOR_REVIEW_OR_LIFECYCLE_EVIDENCE")
        for path in prior_paths
    ]
    expected_siblings = {
        PUBLIC_INVENTORY_PATH,
        CLAIM_TIER_PATH,
        REVIEW_OVERLAY_PATH,
        GITHUB_METADATA_PATH,
        CLAIM_LANGUAGE_PATH,
    }
    if set(sibling_payloads) != expected_siblings:
        fail("COMPOSITION_SIBLING_SET")
    sibling_artifacts = [
        generated_binding(
            path,
            sibling_payloads[path],
            "CH_T003_GENERATED_SIBLING_PRODUCT",
        )
        for path in sorted(sibling_payloads)
    ]
    artifacts = prior_artifacts + sibling_artifacts
    freeze_paths = [item["path"] for item in records]
    candidate_records = candidate["records"]
    candidate_paths = [item["path"] for item in candidate_records]
    overlay_payload = canonical_json(overlay)
    coverage = {
        "freeze_partition": {
            "commit": freeze_commit,
            "tree": freeze_tree,
            "count": len(records),
            "paths_sha256": sha256(canonical_json(freeze_paths)),
            "records_sha256": sha256(canonical_json(records)),
        },
        "candidate_partition": {
            "count": len(candidate_records),
            "added": 8,
            "modified": 1,
            "paths_sha256": sha256(canonical_json(candidate_paths)),
            "records_sha256": sha256(canonical_json(candidate_records)),
            "expected_implementation_count": 434,
        },
        "review_overlay": {
            "path": REVIEW_OVERLAY_PATH,
            "sha256": sha256(overlay_payload),
            "bytes": len(overlay_payload),
        },
        "sibling_products": {
            "count": len(sibling_artifacts),
            "paths": [item["path"] for item in sibling_artifacts],
            "paths_sha256": sha256(
                canonical_json([item["path"] for item in sibling_artifacts])
            ),
        },
    }
    return {
        "schema_version": "1.0.0",
        "schema_id": "haldir.ch-t003.ledger-composition.v1",
        "task_id": TASK_ID,
        "release_target": RELEASE_TARGET,
        "author": AUTHOR,
        "persistent_identifier": None,
        "prior_lifecycle": PRIOR_LIFECYCLE,
        "source": {
            "freeze_commit": freeze_commit,
            "freeze_tree": freeze_tree,
            "composition_path": LEDGER_COMPOSITION_PATH,
            "self_digest_omitted": True,
        },
        "artifacts": artifacts,
        "coverage": coverage,
        "review_boundary": {
            "automated_review_only": True,
            "review_completed_at_i": False,
            "review_required_at_c": True,
            "retroactive_ch_t002_subject_claim": False,
        },
        "bidirectional_references": {
            "overlay_lists_every_freeze_path": (
                [item["path"] for item in overlay["freeze_records"]] == freeze_paths
            ),
            "overlay_lists_exact_candidate_plan": (
                [item["path"] for item in overlay["candidate_records"]]
                == candidate_paths
            ),
            "sibling_artifacts_match_expected_set": (
                {item["path"] for item in sibling_artifacts} == expected_siblings
            ),
        },
        "result": "PASS",
    }


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_utc(value: str) -> str:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None:
        fail("UTC_FORMAT")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise InventoryError("UTC_VALUE") from error
    return value


def publication_records(payloads: Mapping[str, bytes]) -> list[dict[str, Any]]:
    return [
        {
            "path": path,
            "temporary": f"{index:02d}.payload",
            "bytes": len(payloads[path]),
            "sha256": sha256(payloads[path]),
        }
        for index, path in enumerate(OUTPUT_PATHS)
    ]


def publication_candidate_records(
    snapshot: Mapping[str, Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    if snapshot is None:
        return []
    if set(snapshot) != {CLAIM_LEDGER_PATH, PRODUCT_PATH, PRODUCT_TESTS_PATH}:
        fail("CANDIDATE_SNAPSHOT_SET")
    return [
        {
            "path": path,
            "bytes": len(snapshot[path]["payload"]),
            "sha256": sha256(snapshot[path]["payload"]),
        }
        for path in sorted(snapshot)
    ]


def validate_publication_journal(
    payload: bytes,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    value = strict_json(payload, label="publication-journal", maximum=65_536)
    if payload != canonical_json(value) or not isinstance(value, dict):
        fail("PUBLICATION_JOURNAL_CANONICAL")
    if set(value) != {
        "schema_version",
        "task_id",
        "records",
        "candidate_inputs",
    }:
        fail("PUBLICATION_JOURNAL_FIELDS")
    records = value["records"]
    candidate_inputs = value["candidate_inputs"]
    if (
        value["schema_version"] != "1.0.0"
        or value["task_id"] != TASK_ID
        or not isinstance(records, list)
        or len(records) != len(OUTPUT_PATHS)
        or not isinstance(candidate_inputs, list)
        or len(candidate_inputs) not in {0, 3}
    ):
        fail("PUBLICATION_JOURNAL_IDENTITY")
    expected_paths = list(OUTPUT_PATHS)
    for index, record in enumerate(records):
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "temporary", "bytes", "sha256"}
            or record["path"] != expected_paths[index]
            or record["temporary"] != f"{index:02d}.payload"
            or type(record["bytes"]) is not int
            or not 0 < record["bytes"] <= MAX_OUTPUT_BYTES
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        ):
            fail("PUBLICATION_JOURNAL_RECORD")
    expected_candidate_paths = sorted(
        (CLAIM_LEDGER_PATH, PRODUCT_PATH, PRODUCT_TESTS_PATH)
    )
    for index, record in enumerate(candidate_inputs):
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "bytes", "sha256"}
            or record["path"] != expected_candidate_paths[index]
            or type(record["bytes"]) is not int
            or not 0 < record["bytes"] <= MAX_BLOB_BYTES
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        ):
            fail("PUBLICATION_JOURNAL_CANDIDATE")
    return value, records, candidate_inputs


def write_all(descriptor: int, payload: bytes, label: str) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as error:
            raise InventoryError(f"{label}_WRITE") from error
        if written <= 0:
            fail(f"{label}_WRITE")
        offset += written


def output_parent_descriptor(root_descriptor: int, path: str) -> tuple[int, str]:
    try:
        return open_relative_parent(root_descriptor, path, create=False)
    except InventoryError as error:
        raise InventoryError(f"OUTPUT_PARENT:{path}") from error


def revalidate_output_parent(
    root_descriptor: int,
    path: str,
    expected_descriptor: int,
) -> None:
    observed_descriptor, _name = output_parent_descriptor(root_descriptor, path)
    try:
        expected = os.fstat(expected_descriptor)
        observed = os.fstat(observed_descriptor)
        if expected.st_dev != observed.st_dev or expected.st_ino != observed.st_ino:
            fail("OUTPUT_PARENT_CHANGED", path)
    finally:
        os.close(observed_descriptor)


def recover_product_publication(
    repo: Path,
    *,
    retain_committed: bool = True,
) -> dict[str, tuple[int, str]] | None:
    root_descriptor = os.open(
        repo,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    transaction_descriptor = -1
    try:
        try:
            transaction_descriptor = os.open(
                PUBLICATION_TRANSACTION_DIRECTORY,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
        except FileNotFoundError:
            return None
        entries = set(os.listdir(transaction_descriptor))
        markers = entries & {
            PUBLICATION_ACTIVE_MARKER,
            PUBLICATION_COMMITTED_MARKER,
        }
        if not markers:
            allowed_early_entries = {PUBLICATION_JOURNAL_STAGING} | {
                name
                for index in range(len(OUTPUT_PATHS))
                for name in (f"{index:02d}.pending", f"{index:02d}.payload")
            }
            if not entries.issubset(allowed_early_entries):
                fail("PUBLICATION_RECOVERY_MARKER")
            for path in OUTPUT_PATHS:
                parent_descriptor, name = output_parent_descriptor(
                    root_descriptor, path
                )
                try:
                    try:
                        os.stat(
                            name,
                            dir_fd=parent_descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        fail("PUBLICATION_MARKERLESS_TARGET")
                finally:
                    os.close(parent_descriptor)
            for entry in sorted(entries):
                status = os.stat(
                    entry,
                    dir_fd=transaction_descriptor,
                    follow_symlinks=False,
                )
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    fail("PUBLICATION_MARKERLESS_CONTENT")
                os.unlink(entry, dir_fd=transaction_descriptor)
            os.fsync(transaction_descriptor)
            os.close(transaction_descriptor)
            transaction_descriptor = -1
            os.rmdir(PUBLICATION_TRANSACTION_DIRECTORY, dir_fd=root_descriptor)
            os.fsync(root_descriptor)
            return None
        if len(markers) != 1:
            fail("PUBLICATION_RECOVERY_MARKER")
        marker = next(iter(markers))
        journal_payload, _identity = read_regular_at(
            transaction_descriptor,
            marker,
            maximum=65_536,
            label="PUBLICATION_JOURNAL",
        )
        _journal, records, candidate_inputs = validate_publication_journal(
            journal_payload
        )
        allowed_entries = {marker} | {
            name
            for record in records
            for name in (
                record["temporary"],
                record["temporary"].replace(".payload", ".pending"),
            )
        }
        if not entries.issubset(allowed_entries):
            fail("PUBLICATION_RECOVERY_CONTENTS")
        was_committed = marker == PUBLICATION_COMMITTED_MARKER
        committed = was_committed and retain_committed
        if committed and candidate_inputs:
            try:
                current_inputs = candidate_input_snapshot(repo)
            except InventoryError:
                committed = False
            else:
                if [
                    {
                        "path": path,
                        "bytes": len(current_inputs[path]["payload"]),
                        "sha256": sha256(current_inputs[path]["payload"]),
                    }
                    for path in sorted(current_inputs)
                ] != candidate_inputs:
                    committed = False
        recovered = (
            {record["path"]: (record["bytes"], record["sha256"]) for record in records}
            if committed
            else None
        )
        parent_descriptors: dict[str, int] = {}
        try:
            for record in records:
                parent_path = str(PurePosixPath(record["path"]).parent)
                parent_descriptor = parent_descriptors.get(parent_path)
                if parent_descriptor is None:
                    parent_descriptor, _name = output_parent_descriptor(
                        root_descriptor, record["path"]
                    )
                    parent_descriptors[parent_path] = parent_descriptor
                name = PurePosixPath(record["path"]).name
                try:
                    target_status = os.stat(
                        name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    target_status = None
                try:
                    temporary_status = os.stat(
                        record["temporary"],
                        dir_fd=transaction_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    temporary_status = None
                pending_name = record["temporary"].replace(".payload", ".pending")
                try:
                    pending_status = os.stat(
                        pending_name,
                        dir_fd=transaction_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pending_status = None
                if pending_status is not None:
                    if (
                        target_status is not None
                        or temporary_status is not None
                        or not stat.S_ISREG(pending_status.st_mode)
                        or pending_status.st_nlink != 1
                    ):
                        fail("PUBLICATION_PENDING_IDENTITY")
                    os.unlink(pending_name, dir_fd=transaction_descriptor)
                if temporary_status is not None:
                    temporary_payload, _temporary_identity = read_regular_at(
                        transaction_descriptor,
                        record["temporary"],
                        maximum=MAX_OUTPUT_BYTES,
                        label="PUBLICATION_TEMPORARY",
                    )
                    if (
                        len(temporary_payload) != record["bytes"]
                        or sha256(temporary_payload) != record["sha256"]
                    ):
                        fail("PUBLICATION_TEMPORARY_BINDING")
                if committed:
                    if target_status is None:
                        fail("PUBLICATION_COMMITTED_TARGET")
                    target_payload, _target_identity = read_regular_at(
                        parent_descriptor,
                        name,
                        maximum=MAX_OUTPUT_BYTES,
                        label="PUBLICATION_TARGET",
                    )
                    if (
                        len(target_payload) != record["bytes"]
                        or sha256(target_payload) != record["sha256"]
                    ):
                        fail("PUBLICATION_COMMITTED_BINDING")
                elif target_status is not None:
                    if temporary_status is not None:
                        if (
                            target_status.st_dev != temporary_status.st_dev
                            or target_status.st_ino != temporary_status.st_ino
                        ):
                            fail("PUBLICATION_ACTIVE_TARGET_IDENTITY")
                    elif was_committed:
                        target_payload, _target_identity = read_regular_at(
                            parent_descriptor,
                            name,
                            maximum=MAX_OUTPUT_BYTES,
                            label="PUBLICATION_TARGET",
                        )
                        if (
                            len(target_payload) != record["bytes"]
                            or sha256(target_payload) != record["sha256"]
                        ):
                            fail("PUBLICATION_ACTIVE_TARGET_BINDING")
                    else:
                        fail("PUBLICATION_ACTIVE_TARGET_IDENTITY")
                    os.unlink(name, dir_fd=parent_descriptor)
                if temporary_status is not None:
                    os.unlink(record["temporary"], dir_fd=transaction_descriptor)
            for descriptor in parent_descriptors.values():
                os.fsync(descriptor)
        finally:
            for descriptor in parent_descriptors.values():
                os.close(descriptor)
        os.fsync(transaction_descriptor)
        os.unlink(marker, dir_fd=transaction_descriptor)
        os.fsync(transaction_descriptor)
        os.close(transaction_descriptor)
        transaction_descriptor = -1
        os.rmdir(PUBLICATION_TRANSACTION_DIRECTORY, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
        return recovered
    except OSError as error:
        raise InventoryError("PUBLICATION_RECOVERY") from error
    finally:
        if transaction_descriptor >= 0:
            os.close(transaction_descriptor)
        os.close(root_descriptor)


@contextlib.contextmanager
def publication_lock(repo: Path) -> Any:
    root_descriptor = os.open(
        repo,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    lock_descriptor = -1
    created = False
    acquired = False
    try:
        try:
            lock_descriptor = os.open(
                PUBLICATION_LOCK_FILE,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_descriptor,
            )
            created = True
        except FileExistsError:
            lock_descriptor = os.open(
                PUBLICATION_LOCK_FILE,
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
        status = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) & 0o077
        ):
            fail("PUBLICATION_LOCK_IDENTITY")
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise InventoryError("PUBLICATION_BUSY") from error
        acquired = True
        observed = os.stat(
            PUBLICATION_LOCK_FILE,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if observed.st_dev != status.st_dev or observed.st_ino != status.st_ino:
            fail("PUBLICATION_LOCK_CHANGED")
        os.ftruncate(lock_descriptor, 0)
        os.lseek(lock_descriptor, 0, os.SEEK_SET)
        os.fchmod(lock_descriptor, 0o600)
        write_all(
            lock_descriptor,
            PUBLICATION_LOCK_PAYLOAD,
            "PUBLICATION_LOCK",
        )
        os.fsync(lock_descriptor)
        os.fsync(root_descriptor)
        yield
        observed = os.stat(
            PUBLICATION_LOCK_FILE,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if observed.st_dev != status.st_dev or observed.st_ino != status.st_ino:
            fail("PUBLICATION_LOCK_CHANGED")
        os.unlink(PUBLICATION_LOCK_FILE, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    except OSError as error:
        if (created or acquired) and lock_descriptor >= 0:
            try:
                observed = os.stat(
                    PUBLICATION_LOCK_FILE,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                owned = os.fstat(lock_descriptor)
                if observed.st_dev == owned.st_dev and observed.st_ino == owned.st_ino:
                    os.unlink(PUBLICATION_LOCK_FILE, dir_fd=root_descriptor)
            except OSError:
                pass
        raise InventoryError("PUBLICATION_LOCK") from error
    except BaseException:
        if (created or acquired) and lock_descriptor >= 0:
            try:
                observed = os.stat(
                    PUBLICATION_LOCK_FILE,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                owned = os.fstat(lock_descriptor)
                if observed.st_dev == owned.st_dev and observed.st_ino == owned.st_ino:
                    os.unlink(PUBLICATION_LOCK_FILE, dir_fd=root_descriptor)
            except OSError:
                pass
        raise
    finally:
        if lock_descriptor >= 0:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_descriptor)
        os.close(root_descriptor)


def write_products(repo: Path, products: Mapping[str, Any]) -> None:
    repo = repo.resolve(strict=True)
    with publication_lock(repo):
        write_products_locked(repo, products)


def write_products_locked(repo: Path, products: Mapping[str, Any]) -> None:
    if set(products) != set(OUTPUT_PATHS):
        fail("OUTPUT_SET")
    payloads: dict[str, bytes] = {}
    for path in OUTPUT_PATHS:
        payload = canonical_json(products[path])
        if len(payload) > MAX_OUTPUT_BYTES:
            fail("OUTPUT_SIZE", f"{path}:{len(payload)}")
        payloads[path] = payload
    try:
        repo = repo.resolve(strict=True)
        repo_status = repo.lstat()
    except OSError as error:
        raise InventoryError("OUTPUT_REPOSITORY") from error
    if not stat.S_ISDIR(repo_status.st_mode):
        fail("OUTPUT_REPOSITORY_NOT_DIRECTORY")
    recovered = recover_product_publication(repo)
    if recovered is not None:
        if recovered != {
            path: (len(payloads[path]), sha256(payloads[path])) for path in OUTPUT_PATHS
        }:
            fail("PUBLICATION_RECOVERED_PRODUCT_MISMATCH")
        return
    root_descriptor = os.open(
        repo,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    transaction_descriptor = -1
    parent_descriptors: dict[str, int] = {}
    committed = False
    try:
        root_identity = os.fstat(root_descriptor)
        for path in OUTPUT_PATHS:
            parent_path = str(PurePosixPath(path).parent)
            if parent_path not in parent_descriptors:
                descriptor, _name = output_parent_descriptor(root_descriptor, path)
                parent_descriptors[parent_path] = descriptor
            parent_descriptor = parent_descriptors[parent_path]
            name = PurePosixPath(path).name
            try:
                os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise InventoryError(f"OUTPUT_TARGET_STAT:{path}") from error
            else:
                fail("OUTPUT_TARGET_EXISTS", path)
        try:
            os.mkdir(
                PUBLICATION_TRANSACTION_DIRECTORY,
                mode=0o700,
                dir_fd=root_descriptor,
            )
        except FileExistsError as error:
            raise InventoryError("PUBLICATION_TRANSACTION_EXISTS") from error
        transaction_descriptor = os.open(
            PUBLICATION_TRANSACTION_DIRECTORY,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        records = publication_records(payloads)
        candidate_snapshot = getattr(products, "candidate_snapshot", None)
        candidate_records = publication_candidate_records(candidate_snapshot)
        journal = canonical_json(
            {
                "schema_version": "1.0.0",
                "task_id": TASK_ID,
                "records": records,
                "candidate_inputs": candidate_records,
            }
        )
        marker_descriptor = os.open(
            PUBLICATION_JOURNAL_STAGING,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=transaction_descriptor,
        )
        try:
            write_all(marker_descriptor, journal, "PUBLICATION_JOURNAL")
            os.fsync(marker_descriptor)
        finally:
            os.close(marker_descriptor)
        os.fsync(transaction_descriptor)
        os.rename(
            PUBLICATION_JOURNAL_STAGING,
            PUBLICATION_ACTIVE_MARKER,
            src_dir_fd=transaction_descriptor,
            dst_dir_fd=transaction_descriptor,
        )
        os.fsync(transaction_descriptor)
        os.fsync(root_descriptor)
        for record in records:
            pending_name = record["temporary"].replace(".payload", ".pending")
            descriptor = os.open(
                pending_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o644,
                dir_fd=transaction_descriptor,
            )
            try:
                write_all(descriptor, payloads[record["path"]], "PUBLICATION_PAYLOAD")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.rename(
                pending_name,
                record["temporary"],
                src_dir_fd=transaction_descriptor,
                dst_dir_fd=transaction_descriptor,
            )
            os.fsync(transaction_descriptor)
        if candidate_snapshot is not None:
            revalidate_candidate_inputs(repo, candidate_snapshot)
        if (
            os.fstat(root_descriptor).st_dev != root_identity.st_dev
            or os.fstat(root_descriptor).st_ino != root_identity.st_ino
        ):
            fail("OUTPUT_REPOSITORY_CHANGED")
        for record in records:
            path = record["path"]
            parent_descriptor = parent_descriptors[str(PurePosixPath(path).parent)]
            name = PurePosixPath(path).name
            if candidate_snapshot is not None:
                revalidate_candidate_inputs(repo, candidate_snapshot)
            revalidate_output_parent(root_descriptor, path, parent_descriptor)
            try:
                os.link(
                    record["temporary"],
                    name,
                    src_dir_fd=transaction_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise InventoryError(f"OUTPUT_TARGET_EXISTS:{path}") from error
            except OSError as error:
                raise InventoryError(f"OUTPUT_TARGET_CREATE:{path}") from error
            target_status = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            temporary_status = os.stat(
                record["temporary"],
                dir_fd=transaction_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(target_status.st_mode)
                or target_status.st_dev != temporary_status.st_dev
                or target_status.st_ino != temporary_status.st_ino
            ):
                fail("OUTPUT_TARGET_IDENTITY", path)
            revalidate_output_parent(root_descriptor, path, parent_descriptor)
            if candidate_snapshot is not None:
                revalidate_candidate_inputs(repo, candidate_snapshot)
        for descriptor in parent_descriptors.values():
            os.fsync(descriptor)
        if candidate_snapshot is not None:
            revalidate_candidate_inputs(repo, candidate_snapshot)
        os.rename(
            PUBLICATION_ACTIVE_MARKER,
            PUBLICATION_COMMITTED_MARKER,
            src_dir_fd=transaction_descriptor,
            dst_dir_fd=transaction_descriptor,
        )
        os.fsync(transaction_descriptor)
        if candidate_snapshot is not None:
            try:
                revalidate_candidate_inputs(repo, candidate_snapshot)
            except BaseException:
                os.rename(
                    PUBLICATION_COMMITTED_MARKER,
                    PUBLICATION_ACTIVE_MARKER,
                    src_dir_fd=transaction_descriptor,
                    dst_dir_fd=transaction_descriptor,
                )
                os.fsync(transaction_descriptor)
                raise
        committed = True
    except BaseException:
        raise
    finally:
        for descriptor in parent_descriptors.values():
            os.close(descriptor)
        if transaction_descriptor >= 0:
            os.close(transaction_descriptor)
        os.close(root_descriptor)
        try:
            recovered_after_commit = recover_product_publication(
                repo,
                retain_committed=committed,
            )
            if committed and recovered_after_commit != {
                path: (len(payloads[path]), sha256(payloads[path]))
                for path in OUTPUT_PATHS
            }:
                fail("PUBLICATION_COMMIT_REVOKED")
        except BaseException:
            if committed:
                raise
            raise


def generate(
    repo: Path,
    freeze_commit: str,
    *,
    fetch: Callable[[str], tuple[int, dict[str, str], bytes]],
    captured_at_utc: str,
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    freeze_commit = resolve_commit(repo, freeze_commit)
    signature = validate_freeze_trust_anchor(repo, freeze_commit)
    object_format, freeze_tree, entries, blobs = tree_snapshot(repo, freeze_commit)
    records = inventory_records(entries, blobs)
    archives, expanded_contents = inventory_archives(records, blobs)
    candidate_snapshot = candidate_input_snapshot(repo)
    candidate = candidate_implementation(
        repo,
        {item["path"] for item in records},
        candidate_snapshot,
    )
    candidate_ledger = candidate_snapshot[CLAIM_LEDGER_PATH]["payload"]
    with tempfile.TemporaryDirectory(
        prefix="haldir-ch-t003-source-"
    ) as source_directory:
        source_root = Path(source_directory)
        materialize_snapshot(source_root, entries, blobs)
        toolchain = rust_toolchain(source_root)
        cargo = cargo_metadata(source_root, toolchain)
        public_api = capture_public_api(source_root, cargo["metadata"], toolchain)
        cli = capture_cli_inventory(
            source_root,
            records,
            blobs,
            cargo["metadata"],
            toolchain,
        )
    ipc = capture_ipc(blobs)
    schemas = capture_schema_inventory(records, blobs)
    documentation = capture_documentation(records)
    public = build_public_inventory(
        freeze_commit=freeze_commit,
        freeze_tree=freeze_tree,
        object_format=object_format,
        signature=signature,
        records=records,
        archives=archives,
        toolchain=toolchain,
        cargo=cargo,
        public_api=public_api,
        cli=cli,
        ipc=ipc,
        schemas=schemas,
        documentation=documentation,
        candidate=candidate,
    )
    tier = build_claim_tier_ledger(
        candidate_ledger,
        blobs[CLAIM_LEDGER_PATH],
        blobs[CLAIMS_STATE_PATH],
        records,
        freeze_commit,
        freeze_tree,
    )
    github = capture_github(fetch, captured_at_utc=captured_at_utc)
    if github["normalized"]["default_branch_head"] != freeze_commit:
        fail(
            "GITHUB_DEFAULT_BRANCH_HEAD",
            str(github["normalized"]["default_branch_head"]),
        )
    language = build_claim_language(
        freeze_commit,
        freeze_tree,
        records,
        blobs,
        archives,
        expanded_contents,
        cli,
        github,
        candidate_ledger,
    )
    overlay = build_review_overlay(
        repo,
        freeze_commit,
        freeze_tree,
        records,
        blobs,
        candidate,
    )
    siblings = {
        PUBLIC_INVENTORY_PATH: canonical_json(public),
        CLAIM_TIER_PATH: canonical_json(tier),
        REVIEW_OVERLAY_PATH: canonical_json(overlay),
        GITHUB_METADATA_PATH: canonical_json(github),
        CLAIM_LANGUAGE_PATH: canonical_json(language),
    }
    composition = build_ledger_composition(
        freeze_commit=freeze_commit,
        freeze_tree=freeze_tree,
        records=records,
        candidate=candidate,
        overlay=overlay,
        sibling_payloads=siblings,
    )
    products = {
        PUBLIC_INVENTORY_PATH: public,
        CLAIM_TIER_PATH: tier,
        REVIEW_OVERLAY_PATH: overlay,
        LEDGER_COMPOSITION_PATH: composition,
        GITHUB_METADATA_PATH: github,
        CLAIM_LANGUAGE_PATH: language,
    }
    # Check all products before the caller can write any file.
    for path, value in products.items():
        size = len(canonical_json(value))
        if size > MAX_OUTPUT_BYTES:
            fail("OUTPUT_SIZE", f"{path}:{size}")
    return GeneratedProducts(products, candidate_snapshot)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    generate_command = commands.add_parser(
        "generate",
        help="Generate the six implementation products from the freeze commit.",
    )
    generate_command.add_argument("--repo", default=".")
    generate_command.add_argument("--freeze-commit", required=True)
    generate_command.add_argument(
        "--captured-at-utc",
        help="Use an explicit UTC second. The default is the current UTC second.",
    )
    verify_command = commands.add_parser(
        "verify",
        help="Verify the exact implementation products with the registered verifier.",
    )
    verify_command.add_argument("--repo", default=".")
    verify_command.add_argument("--implementation-commit", required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        repo = Path(arguments.repo)
        if arguments.command == "verify":
            result = verify_products(repo, arguments.implementation_commit)
            sys.stdout.write(canonical_json(result).decode("utf-8"))
            return 0
        captured_at = validate_utc(arguments.captured_at_utc or utc_now())
        token = github_token(repo)
        products = generate(
            repo,
            arguments.freeze_commit,
            fetch=live_github_fetch(token),
            captured_at_utc=captured_at,
        )
        write_products(repo, products)
    except (InventoryError, OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"current-public-surface-inventory: FAIL: {error}", file=sys.stderr)
        return 1
    print("current-public-surface-inventory: PASS")
    for path in OUTPUT_PATHS:
        print(f"{path} {len(canonical_json(products[path]))} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
