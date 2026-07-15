#!/usr/bin/env python3
"""Profile fail-closed resource boundaries in verify-current-audit.py.

The profiler executes the exact verifier bytes it hashes and exercises every
declared byte and JSON-structure boundary primitive directly. Each boundary is
sampled immediately at and one unit beyond its limit. Public composition and
timeout wiring remain the responsibility of the verifier's exact test suite.
Timing values are diagnostic evidence only; they are not latency acceptance
criteria.
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import platform
import re
import secrets
import stat
import struct
import sys
import tempfile
import time
import types
import zipfile
import zlib
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence, cast


SCHEMA_VERSION = "1.0.0"
PROFILE_ID = "HALDIR_CURRENT_AUDIT_RESOURCE_BOUNDARY_PROFILE"
SAMPLES_PER_CASE = 3
LIMIT_NAMES = (
    "MAX_JSON_BYTES",
    "MAX_JSON_STRING_BYTES",
    "MAX_REQUIREMENTS_BYTES",
    "MAX_COMPRESSED_LOG_BYTES",
    "MAX_LOG_BYTES",
    "MAX_GIT_BYTES",
    "MAX_HYGIENE_TOTAL_BYTES",
    "MAX_REVOCATION_CAUSE_FILE_BYTES",
    "MAX_REVOCATION_CAUSE_TOTAL_BYTES",
    "MAX_PROTOCOL_PATH_BYTES",
    "MAX_VERIFIER_OUTPUT_BYTES",
    "MAX_ZIP_ENTRY_BYTES",
    "MAX_ZIP_TOTAL_BYTES",
)
JSON_STRUCTURE_LIMIT_NAMES = (
    "MAX_JSON_DEPTH",
    "MAX_JSON_NODES",
    "MAX_JSON_CONTAINER_ENTRIES",
)
EXPECTED_LIMITS_BYTES = {
    "MAX_JSON_BYTES": 256 * 1024,
    "MAX_JSON_STRING_BYTES": 256 * 1024,
    "MAX_REQUIREMENTS_BYTES": 4 * 1024 * 1024,
    "MAX_COMPRESSED_LOG_BYTES": 256 * 1024,
    "MAX_LOG_BYTES": 4 * 1024 * 1024,
    "MAX_GIT_BYTES": 8 * 1024 * 1024,
    "MAX_HYGIENE_TOTAL_BYTES": 512 * 1024 * 1024,
    "MAX_REVOCATION_CAUSE_FILE_BYTES": 4 * 1024 * 1024,
    "MAX_REVOCATION_CAUSE_TOTAL_BYTES": 16 * 1024 * 1024,
    "MAX_PROTOCOL_PATH_BYTES": 240,
    "MAX_VERIFIER_OUTPUT_BYTES": 64 * 1024,
    "MAX_ZIP_ENTRY_BYTES": 4 * 1024 * 1024,
    "MAX_ZIP_TOTAL_BYTES": 16 * 1024 * 1024,
}
EXPECTED_JSON_STRUCTURE_LIMITS = {
    "MAX_JSON_DEPTH": 64,
    "MAX_JSON_NODES": 32_768,
    "MAX_JSON_CONTAINER_ENTRIES": 16_384,
}
REQUIRED_CALLABLES = (
    "_load_json",
    "_validate_json_structure",
    "_read_gzip_evidence",
    "_verify_handoff_zip",
    "_git",
    "_bounded_hygiene_total",
    "_bounded_revocation_cause_total",
    "_require_protocol_path",
    "_require_verifier_output_bound",
    "_run_bounded",
    "_sanitized_git_environment",
    "_verify_trusted_executable",
)
REQUIRED_ATTRIBUTES = ("GIT_EXECUTABLE",)
EXPECTED_GIT_EXECUTABLE = "/usr/bin/git"
GIT_FIXTURE_SEAM = {
    "executable_override": "PRIVATE_TEMPORARY_ABSOLUTE_PATH",
    "trust_override": "EXACT_PRIVATE_FIXTURE_ONLY",
    "interpreter": "ROOT_OWNED_RESOLVED_POSIX_SHELL",
    "ambient_path_lookup": False,
    "purpose": "GIT_STDOUT_STDERR_BOUNDARY_INJECTION",
}
TIMING_CLASSIFICATION = "DIAGNOSTIC_NON_COMPARABLE"
TIMING_STATEMENT = (
    "Elapsed nanosecond samples are diagnostic and non-comparable across runs; "
    "they make no latency acceptance claim."
)
TIMEOUT_CLASSIFICATION = "OUT_OF_SCOPE_REQUIRES_SEPARATE_TEST_EVIDENCE"
TIMEOUT_STATEMENT = (
    "Process timeout is not a byte resource maximum and is not profiled by "
    "these cases; its public wiring must be established by the exact verifier "
    "test suite."
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)


class ProfileError(RuntimeError):
    """The resource profile could not be produced or is structurally invalid."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _constant_integer(node: ast.expr, label: str) -> int:
    """Evaluate a small, side-effect-free integer constant expression."""

    if isinstance(node, ast.Constant) and type(node.value) is int:
        value = node.value
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd):
        value = _constant_integer(node.operand, label)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
        left = _constant_integer(node.left, label)
        right = _constant_integer(node.right, label)
        value = left + right if isinstance(node.op, ast.Add) else left * right
    else:
        raise ProfileError(
            f"verifier limit is not a literal integer expression: {label}"
        )
    if value <= 0 or value > (1 << 63) - 1:
        raise ProfileError(f"verifier limit is outside the supported range: {label}")
    return value


def _verifier_limit_values(payload: bytes) -> dict[str, int]:
    """Extract the profiled limits from the exact verifier source bytes."""

    try:
        tree = ast.parse(payload, filename="verify-current-audit.py", mode="exec")
    except (SyntaxError, ValueError) as error:
        raise ProfileError("cannot parse verifier limits") from error
    values: dict[str, int] = {}
    declared_byte_limits: set[str] = set()
    for statement in tree.body:
        target: ast.expr | None = None
        value_node: ast.expr | None = None
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value_node = statement.value
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
            value_node = statement.value
        if not isinstance(target, ast.Name) or value_node is None:
            continue
        if re.fullmatch(r"MAX_[A-Z0-9_]*BYTES", target.id) is None:
            continue
        declared_byte_limits.add(target.id)
        if target.id not in LIMIT_NAMES:
            continue
        if target.id in values:
            raise ProfileError(
                f"verifier limit is assigned more than once: {target.id}"
            )
        values[target.id] = _constant_integer(value_node, target.id)
    if declared_byte_limits != set(LIMIT_NAMES) or set(values) != set(LIMIT_NAMES):
        raise ProfileError(
            "verifier does not declare every profiled limit exactly once"
        )
    return values


def _verifier_json_structure_values(payload: bytes) -> dict[str, int]:
    """Extract every declared JSON structural limit from verifier source."""

    try:
        tree = ast.parse(payload, filename="verify-current-audit.py", mode="exec")
    except (SyntaxError, ValueError) as error:
        raise ProfileError("cannot parse verifier JSON structural limits") from error
    values: dict[str, int] = {}
    declared_json_limits: set[str] = set()
    for statement in tree.body:
        target: ast.expr | None = None
        value_node: ast.expr | None = None
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value_node = statement.value
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
            value_node = statement.value
        if (
            not isinstance(target, ast.Name)
            or value_node is None
            or not target.id.startswith("MAX_JSON_")
        ):
            continue
        declared_json_limits.add(target.id)
        if target.id not in JSON_STRUCTURE_LIMIT_NAMES:
            continue
        if target.id in values:
            raise ProfileError(
                f"verifier JSON limit is assigned more than once: {target.id}"
            )
        values[target.id] = _constant_integer(value_node, target.id)
    expected_declarations = {
        name for name in LIMIT_NAMES if name.startswith("MAX_JSON_")
    } | set(JSON_STRUCTURE_LIMIT_NAMES)
    if declared_json_limits != expected_declarations or set(values) != set(
        JSON_STRUCTURE_LIMIT_NAMES
    ):
        raise ProfileError(
            "verifier does not declare every profiled JSON limit exactly once"
        )
    return values


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _load_verifier(path: Path) -> tuple[types.ModuleType, bytes]:
    """Execute and return exactly the verifier bytes that were hashed.

    A path-based import would reopen ``path`` after the first read.  A
    concurrent ABA replacement could therefore execute different bytes and
    restore the hashed bytes before the post-load check.  Compiling the
    captured payload directly binds the executed implementation to its digest.
    The second read additionally rejects a verifier that remained changed.
    """

    try:
        before = path.read_bytes()
    except OSError as error:
        raise ProfileError(f"cannot read verifier: {path}") from error
    if not before:
        raise ProfileError("verifier file is empty")
    if _verifier_limit_values(before) != EXPECTED_LIMITS_BYTES:
        raise ProfileError("verifier byte limits are unsupported by this profiler")
    if _verifier_json_structure_values(before) != EXPECTED_JSON_STRUCTURE_LIMITS:
        raise ProfileError(
            "verifier JSON structural limits are unsupported by this profiler"
        )

    module_name = f"haldir_current_audit_verifier_{_sha256(before)[:16]}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    had_prior_module = module_name in sys.modules
    prior_module = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        code = compile(before, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException as error:
        raise ProfileError(f"cannot execute verifier snapshot: {path}") from error
    finally:
        if had_prior_module:
            # ``None`` is a valid import-blocking sentinel in ``sys.modules``;
            # preserve it exactly even though typeshed narrows the mapping.
            sys.modules[module_name] = cast(types.ModuleType, prior_module)
        else:
            sys.modules.pop(module_name, None)

    try:
        after = path.read_bytes()
    except OSError as error:
        raise ProfileError(f"cannot re-read verifier: {path}") from error
    if before != after:
        raise ProfileError("verifier changed while it was being imported")

    for name in (
        *LIMIT_NAMES,
        *JSON_STRUCTURE_LIMIT_NAMES,
        "CurrentAuditError",
        *REQUIRED_ATTRIBUTES,
        *REQUIRED_CALLABLES,
    ):
        if not hasattr(module, name):
            raise ProfileError(f"verifier member is missing: {name}")
    runtime_limits = {name: getattr(module, name) for name in LIMIT_NAMES}
    if any(type(value) is not int for value in runtime_limits.values()):
        raise ProfileError("verifier runtime limit is not an integer")
    if runtime_limits != EXPECTED_LIMITS_BYTES:
        raise ProfileError("verifier runtime limits contradict its declarations")
    runtime_json_limits = {
        name: getattr(module, name) for name in JSON_STRUCTURE_LIMIT_NAMES
    }
    if any(type(value) is not int for value in runtime_json_limits.values()):
        raise ProfileError("verifier runtime JSON limit is not an integer")
    if runtime_json_limits != EXPECTED_JSON_STRUCTURE_LIMITS:
        raise ProfileError("verifier runtime JSON limits contradict their declarations")
    if module.MAX_ZIP_TOTAL_BYTES <= module.MAX_ZIP_ENTRY_BYTES:
        raise ProfileError("verifier ZIP limits cannot produce a valid aggregate case")
    for name in REQUIRED_ATTRIBUTES:
        value = getattr(module, name)
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ProfileError(f"verifier executable is not an absolute path: {name}")
    if module.GIT_EXECUTABLE != EXPECTED_GIT_EXECUTABLE:
        raise ProfileError("verifier Git executable is unsupported")
    error_type = module.CurrentAuditError
    if not isinstance(error_type, type) or not issubclass(error_type, Exception):
        raise ProfileError("verifier CurrentAuditError is not an exception type")
    for name in REQUIRED_CALLABLES:
        if not callable(getattr(module, name)):
            raise ProfileError(f"verifier member is not callable: {name}")
    return module, before


def _error_text(error: BaseException) -> str:
    text = str(error)
    return text if text else type(error).__name__


def _empty_fixture() -> dict[str, Any]:
    return {
        "file_bytes": None,
        "decompressed_bytes": None,
        "zip_archive_bytes": None,
        "zip_entry_count": None,
        "zip_largest_entry_bytes": None,
        "zip_total_uncompressed_bytes": None,
        "git_stdout_bytes": None,
        "git_stderr_bytes": None,
        "hygiene_total_bytes": None,
        "hygiene_current_bytes": None,
        "hygiene_increment_bytes": None,
        "revocation_cause_total_bytes": None,
        "revocation_cause_current_bytes": None,
        "revocation_cause_file_bytes": None,
        "protocol_path_bytes": None,
        "verifier_output_bytes": None,
        "json_depth": None,
        "json_nodes": None,
        "json_string_bytes": None,
        "json_container_entries": None,
    }


def _measure_case(
    *,
    case_id: str,
    primitive: str,
    limit_name: str,
    subject: str,
    unit: str,
    limit_value: int,
    input_value: int,
    fixture: dict[str, Any],
    expected_outcome: str,
    expected_error_code: str | None,
    action: Callable[[], object],
    expected_exception: type[BaseException],
) -> dict[str, Any]:
    elapsed: list[int] = []
    accepted = 0
    rejected = 0
    errors: list[str] = []

    for _ in range(SAMPLES_PER_CASE):
        started = time.perf_counter_ns()
        try:
            action()
        except expected_exception as error:
            rejected += 1
            errors.append(_error_text(error))
        except BaseException as error:  # Evidence must preserve unexpected failures.
            rejected += 1
            errors.append(f"UNEXPECTED_{type(error).__name__}:{_error_text(error)}")
        else:
            accepted += 1
        finally:
            elapsed.append(time.perf_counter_ns() - started)

    observed_outcome = (
        "ACCEPT"
        if accepted == SAMPLES_PER_CASE
        else "REJECT"
        if rejected == SAMPLES_PER_CASE
        else "MIXED"
    )
    error_codes = sorted(set(errors))
    passed = observed_outcome == expected_outcome
    if expected_outcome == "ACCEPT":
        passed = passed and not error_codes and expected_error_code is None
    else:
        passed = passed and error_codes == [expected_error_code]

    ordered = sorted(elapsed)
    return {
        "id": case_id,
        "primitive": primitive,
        "limit_name": limit_name,
        "subject": subject,
        "unit": unit,
        "limit_value": limit_value,
        "input_value": input_value,
        "fixture": fixture,
        "expected_outcome": expected_outcome,
        "observed_outcome": observed_outcome,
        "expected_error_code": expected_error_code,
        "observed_error_codes": error_codes,
        "accepted_samples": accepted,
        "rejected_samples": rejected,
        "elapsed_ns": {
            "samples": elapsed,
            "min": ordered[0],
            "median": ordered[len(ordered) // 2],
            "max": ordered[-1],
        },
        "pass": passed,
    }


def _valid_root_json(size: int) -> bytes:
    root = b'{"payload":"\xc3\xa9"}'
    if size < len(root):
        raise ProfileError("JSON resource limit is too small for a root-object fixture")
    # The multibyte value distinguishes a raw-byte cap from a decoded-character
    # mutant. JSON trailing whitespace reaches the target without confounding
    # the independently profiled aggregate-string boundary.
    return root + (b" " * (size - len(root)))


def _utf8_payload_exact(size: int) -> bytes:
    """Return exact-size valid UTF-8, using multibyte code points where possible."""

    if type(size) is not int or size < 0:
        raise ProfileError("UTF-8 fixture size is invalid")
    payload = ("é" * (size // 2) + ("u" if size % 2 else "")).encode("utf-8")
    if len(payload) != size:
        raise ProfileError("UTF-8 fixture has the wrong byte length")
    return payload


def _protocol_path_fixture(size: int) -> str:
    """Return one canonical relative path with exactly ``size`` UTF-8 bytes."""

    if type(size) is not int or size < 5:
        raise ProfileError("protocol-path fixture size is invalid")

    def component(byte_count: int, odd_tail: str) -> str:
        value = ("é" * (byte_count // 2)) + (odd_tail if byte_count % 2 else "")
        if len(value.encode("utf-8")) != byte_count:
            raise ProfileError("protocol-path component encoding is invalid")
        return value

    content_bytes = size - 1  # One separator between two nonempty components.
    first_bytes = content_bytes // 2
    second_bytes = content_bytes - first_bytes
    first = component(first_bytes, "a")
    second = component(second_bytes, "b")
    path = f"{first}/{second}"
    if (
        not first
        or not second
        or max(first_bytes, second_bytes) >= size
        or len(path.encode("utf-8")) != size
        or PurePosixPath(path).is_absolute()
        or PurePosixPath(path).as_posix() != path
    ):
        raise ProfileError("cannot construct protocol-path boundary fixture")
    return path


def _json_structure_dimensions(value: Any) -> dict[str, int]:
    """Count one fixture using the verifier's documented JSON semantics."""

    nodes = 0
    string_bytes = 0
    container_entries = 0
    maximum_depth = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        maximum_depth = max(maximum_depth, depth)
        nodes += 1
        if isinstance(item, str):
            string_bytes += len(item.encode("utf-8"))
        elif isinstance(item, list):
            container_entries += len(item)
            stack.extend((child, depth + 1) for child in reversed(item))
        elif isinstance(item, dict):
            container_entries += len(item)
            for key, child in reversed(tuple(item.items())):
                maximum_depth = max(maximum_depth, depth + 1)
                nodes += 1
                string_bytes += len(key.encode("utf-8"))
                stack.append((child, depth + 1))
        elif item is None or isinstance(item, (bool, int)):
            pass
        else:
            raise ProfileError("JSON structural fixture contains an invalid value")
    return {
        "json_depth": maximum_depth,
        "json_nodes": nodes,
        "json_string_bytes": string_bytes,
        "json_container_entries": container_entries,
    }


def _json_depth_fixture(depth: int) -> tuple[dict[str, Any], dict[str, int]]:
    if type(depth) is not int or depth < 2:
        raise ProfileError("JSON depth fixture is invalid")
    child: Any = 0
    for _ in range(depth - 2):
        child = [child]
    value = {"": child}
    dimensions = _json_structure_dimensions(value)
    if dimensions != {
        "json_depth": depth,
        "json_nodes": depth + 1,
        "json_string_bytes": 0,
        "json_container_entries": depth - 1,
    }:
        raise ProfileError("JSON depth fixture dimensions are invalid")
    return value, dimensions


def _json_node_fixture(nodes: int) -> tuple[dict[str, Any], dict[str, int]]:
    node_limit = EXPECTED_JSON_STRUCTURE_LIMITS["MAX_JSON_NODES"]
    entry_limit = EXPECTED_JSON_STRUCTURE_LIMITS["MAX_JSON_CONTAINER_ENTRIES"]
    if nodes == node_limit:
        members = (nodes - 2) // 2
        value: dict[str, Any] = {f"k{index:05d}": 0 for index in range(members)}
        value["k00000"] = [0]
        expected_depth = 3
    elif nodes == node_limit + 1:
        members = (nodes - 1) // 2
        value = {f"k{index:05d}": 0 for index in range(members)}
        expected_depth = 2
    else:
        raise ProfileError("JSON node fixture size is unsupported")
    dimensions = _json_structure_dimensions(value)
    expected = {
        "json_depth": expected_depth,
        "json_nodes": nodes,
        "json_string_bytes": 6 * members,
        "json_container_entries": entry_limit,
    }
    if dimensions != expected:
        raise ProfileError("JSON node fixture dimensions are invalid")
    return value, dimensions


def _json_string_fixture(size: int) -> tuple[dict[str, Any], dict[str, int]]:
    if type(size) is not int or size < 4:
        raise ProfileError("JSON string fixture size is invalid")

    def exact_utf8_text(byte_count: int, odd_tail: str) -> str:
        text = ("é" * (byte_count // 2)) + (odd_tail if byte_count % 2 else "")
        if len(text.encode("utf-8")) != byte_count:
            raise ProfileError("JSON string fixture encoding is invalid")
        return text

    key_bytes = size // 2
    value_bytes = size - key_bytes
    key = exact_utf8_text(key_bytes, "k")
    text = exact_utf8_text(value_bytes, "v")
    if not key or not text or key_bytes >= size or value_bytes >= size:
        raise ProfileError("JSON string fixture does not isolate aggregation")
    value = {key: text}
    dimensions = _json_structure_dimensions(value)
    if dimensions != {
        "json_depth": 2,
        "json_nodes": 3,
        "json_string_bytes": size,
        "json_container_entries": 1,
    }:
        raise ProfileError("JSON string fixture dimensions are invalid")
    return value, dimensions


def _json_container_fixture(entries: int) -> tuple[dict[str, Any], dict[str, int]]:
    if type(entries) is not int or entries < 1:
        raise ProfileError("JSON container fixture is invalid")
    value = {"": [0] * (entries - 1)}
    dimensions = _json_structure_dimensions(value)
    if dimensions != {
        "json_depth": 3,
        "json_nodes": entries + 2,
        "json_string_bytes": 0,
        "json_container_entries": entries,
    }:
        raise ProfileError("JSON container fixture dimensions are invalid")
    return value, dimensions


def _deterministic_gzip(payload: bytes) -> bytes:
    """Return the canonical gzip representation required by the verifier."""

    compressed = bytearray(gzip.compress(payload, compresslevel=9, mtime=0))
    if len(compressed) < 10:
        raise ProfileError("gzip encoder returned a truncated stream")
    # RFC 1952 makes the OS byte informational.  Normalize it to the Unix value
    # required by the verifier without changing the DEFLATE body.
    compressed[9] = 3
    expected_header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03"
    if not bytes(compressed).startswith(expected_header):
        raise ProfileError("cannot produce the verifier's canonical gzip header")
    return bytes(compressed)


def _exact_size_canonical_gzip(size: int) -> tuple[bytes, bytes]:
    """Produce one canonical gzip member of exactly ``size`` bytes.

    RFC 1951 stored blocks make the encoded size algebraic, avoiding trailing
    bytes that a strict single-member decoder correctly rejects.
    """

    if type(size) is not int or size < 23:
        raise ProfileError("compressed-log limit is too small for a gzip member")
    deflate_bytes = size - 18  # Ten-byte header plus eight-byte trailer.
    block_count = max(1, (deflate_bytes + 65_539) // 65_540)
    payload_bytes = deflate_bytes - (5 * block_count)
    if payload_bytes < 0 or payload_bytes > 65_535 * block_count:
        raise ProfileError("cannot construct exact-size stored gzip fixture")
    payload = _utf8_payload_exact(payload_bytes)
    remaining = payload_bytes
    offset = 0
    blocks = bytearray()
    for index in range(block_count):
        block_bytes = min(remaining, 65_535)
        final = index == block_count - 1
        blocks.append(1 if final else 0)
        blocks.extend(struct.pack("<HH", block_bytes, block_bytes ^ 0xFFFF))
        blocks.extend(payload[offset : offset + block_bytes])
        offset += block_bytes
        remaining -= block_bytes
    if remaining != 0 or offset != len(payload):
        raise ProfileError("stored gzip fixture accounting is invalid")
    header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03"
    trailer = struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload))
    compressed = header + bytes(blocks) + trailer
    if len(compressed) != size:
        raise ProfileError("stored gzip fixture has the wrong encoded size")
    try:
        decoded = gzip.decompress(compressed)
    except (OSError, EOFError) as error:
        raise ProfileError("stored-block gzip fixture is not accepted") from error
    if decoded != payload:
        raise ProfileError("stored-block gzip fixture changed the payload")
    return payload, compressed


def _gzip_record(path: Path, payload: bytes, compressed: bytes) -> dict[str, Any]:
    return {
        "path": path.name,
        "compressed_sha256": _sha256(compressed),
        "compressed_bytes": len(compressed),
        "uncompressed_sha256": _sha256(payload),
        "uncompressed_bytes": len(payload),
        "uncompressed_lines": len(payload.splitlines()),
    }


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def _deterministic_zip(entry_sizes: Sequence[int]) -> bytes:
    if not entry_sizes or any(
        type(size) is not int or size < 0 for size in entry_sizes
    ):
        raise ProfileError("ZIP fixture entry sizes are invalid")
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for index, size in enumerate(entry_sizes):
            archive.writestr(
                _zip_info(f"entry-{index:03d}.bin"),
                _utf8_payload_exact(size),
            )
    payload = output.getvalue()
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            observed = [entry.file_size for entry in archive.infolist()]
            failing = archive.testzip()
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ProfileError(
            "cannot produce a valid deterministic ZIP fixture"
        ) from error
    if observed != list(entry_sizes) or failing is not None:
        raise ProfileError("deterministic ZIP fixture has invalid inventory or CRC")
    return payload


def _split_zip_total(total: int, entry_limit: int) -> list[int]:
    if total <= 0 or entry_limit <= 0:
        raise ProfileError("ZIP aggregate fixture limits are invalid")
    sizes: list[int] = []
    remaining = total
    while remaining:
        size = min(remaining, entry_limit)
        sizes.append(size)
        remaining -= size
    return sizes


def _write_fake_git(directory: Path, *, size: int, stream_name: str) -> Path:
    if os.name != "posix":
        raise ProfileError("fake-git PATH boundary profiling requires POSIX")
    executable = directory / "git"
    if type(size) is not int or size < 0 or stream_name not in {"stdout", "stderr"}:
        raise ProfileError("fake-git fixture parameters are invalid")
    try:
        interpreter = Path("/bin/sh").resolve(strict=True)
        interpreter_metadata = interpreter.stat()
    except OSError as error:
        raise ProfileError("cannot resolve the POSIX shell interpreter") from error
    if (
        not interpreter.is_absolute()
        or interpreter.is_symlink()
        or not stat.S_ISREG(interpreter_metadata.st_mode)
        or interpreter_metadata.st_uid != 0
        or interpreter_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or "\n" in str(interpreter)
        or "\r" in str(interpreter)
    ):
        raise ProfileError("POSIX shell interpreter is not trusted")
    chunk_size = 4096
    repetitions, remainder = divmod(size, chunk_size)
    redirect = " >&2" if stream_name == "stderr" else ""
    chunk = _utf8_payload_exact(chunk_size).decode("utf-8")
    tail = _utf8_payload_exact(remainder).decode("utf-8")
    script = f"""#!{interpreter}
chunk='{chunk}'
index=0
while [ "$index" -lt {repetitions} ]; do
    printf '%s' "$chunk"{redirect}
    index=$((index + 1))
done
printf '%s' '{tail}'{redirect}
""".encode("utf-8")
    executable.write_bytes(script)
    executable.chmod(
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IXOTH
    )
    return executable


def _private_fixture_identity(path: Path) -> tuple[int, int, int, int, int, int, int]:
    """Return a stable identity for one private executable test fixture."""

    try:
        metadata = path.lstat()
        parent_metadata = path.parent.lstat()
    except OSError as error:
        raise ProfileError("cannot inspect fake-git fixture") from error
    current_uid = os.getuid()
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or metadata.st_uid != current_uid
        or parent_metadata.st_uid != current_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ProfileError("fake-git fixture is not private and stable")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _physical_memory() -> tuple[int, str]:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError) as error:
        raise ProfileError("cannot determine physical memory") from error
    if (
        type(pages) is not int
        or type(page_size) is not int
        or pages <= 0
        or page_size <= 0
    ):
        raise ProfileError("physical-memory sysconf values are invalid")
    return pages * page_size, "os.sysconf(SC_PHYS_PAGES*SC_PAGE_SIZE)"


def _tool_environment(verifier: types.ModuleType) -> dict[str, Any]:
    git = getattr(verifier, "GIT_EXECUTABLE", None)
    if not isinstance(git, str) or not Path(git).is_absolute():
        raise ProfileError("verifier Git executable is invalid")
    try:
        verifier._verify_trusted_executable(git, "git")
    except verifier.CurrentAuditError as error:
        raise ProfileError("verifier Git executable is untrusted") from error
    except BaseException as error:
        raise ProfileError(
            "verifier Git trust check terminated unexpectedly"
        ) from error
    try:
        environment = verifier._sanitized_git_environment()
    except BaseException as error:
        raise ProfileError("cannot construct the verifier Git environment") from error
    if not isinstance(environment, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise ProfileError("verifier Git environment is invalid")
    try:
        returncode, stdout, stderr = verifier._run_bounded(
            [git, "--version"],
            cwd=Path.cwd().resolve(),
            env=environment,
            timeout_seconds=10,
            stdout_limit=256,
            stderr_limit=256,
            error_prefix="CURRENT_AUDIT_PROFILE_GIT_VERSION",
        )
    except verifier.CurrentAuditError as error:
        raise ProfileError("cannot determine bounded git version") from error
    except BaseException as error:
        raise ProfileError(
            "bounded Git version probe terminated unexpectedly"
        ) from error
    if returncode != 0 or stderr or not stdout or len(stdout) > 256:
        raise ProfileError("git version output is invalid")
    try:
        verifier._verify_trusted_executable(git, "git")
    except verifier.CurrentAuditError as error:
        raise ProfileError("verifier Git executable changed trust state") from error
    except BaseException as error:
        raise ProfileError(
            "verifier Git trust recheck terminated unexpectedly"
        ) from error
    try:
        git_version = stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ProfileError("git version output is not UTF-8") from error
    if not git_version or "\n" in git_version or "\r" in git_version:
        raise ProfileError("git version output is invalid")
    logical_cpu_count = os.cpu_count()
    if type(logical_cpu_count) is not int or logical_cpu_count <= 0:
        raise ProfileError("cannot determine logical CPU count")
    physical_memory_bytes, physical_memory_source = _physical_memory()
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "hardware": {
            "logical_cpu_count": logical_cpu_count,
            "physical_memory_bytes": physical_memory_bytes,
            "physical_memory_source": physical_memory_source,
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "tools": {
            "git": git_version,
            "git_path": git,
            "zlib_compile": zlib.ZLIB_VERSION,
            "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION,
        },
    }


def _display_path(path: Path) -> str:
    """Prefer a portable working-directory-relative verifier path."""

    try:
        return path.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return str(path)


def _fixture(**updates: int | None) -> dict[str, Any]:
    fixture = _empty_fixture()
    if not set(updates).issubset(fixture):
        raise ProfileError("internal fixture dimension is invalid")
    fixture.update(updates)
    return fixture


def generate_profile(verifier_path: Path) -> dict[str, Any]:
    """Run all boundary samples and return validated JSON-compatible evidence."""

    verifier_path = verifier_path.resolve()
    verifier, verifier_payload = _load_verifier(verifier_path)
    limits = {name: getattr(verifier, name) for name in LIMIT_NAMES}
    json_structure_limits = {
        name: getattr(verifier, name) for name in JSON_STRUCTURE_LIMIT_NAMES
    }
    cases: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="haldir-resource-profile-") as raw:
        root = Path(raw)

        for limit_name in ("MAX_JSON_BYTES", "MAX_REQUIREMENTS_BYTES"):
            limit = limits[limit_name]
            path = root / f"{limit_name}.json"
            label = f"profile.json.{limit_name}"
            for suffix, size, expected, error_code in (
                ("exact", limit, "ACCEPT", None),
                (
                    "over",
                    limit + 1,
                    "REJECT",
                    f"CURRENT_AUDIT_RESOURCE_BOUND:{label}",
                ),
            ):
                payload = _valid_root_json(size)
                path.write_bytes(payload)
                cases.append(
                    _measure_case(
                        case_id=f"load_json.{limit_name}.{suffix}",
                        primitive="_load_json",
                        limit_name=limit_name,
                        subject="JSON_FILE_BYTES",
                        unit="BYTES",
                        limit_value=limit,
                        input_value=size,
                        fixture=_fixture(file_bytes=len(payload)),
                        expected_outcome=expected,
                        expected_error_code=error_code,
                        action=partial(verifier._load_json, path, limit, label),
                        expected_exception=verifier.CurrentAuditError,
                    )
                )

        gzip_path = root / "profile.log.gz"
        compressed_limit = limits["MAX_COMPRESSED_LOG_BYTES"]
        compressed_label = "profile.gzip.compressed"
        for suffix, size, expected, error_code in (
            ("exact", compressed_limit, "ACCEPT", None),
            (
                "over",
                compressed_limit + 1,
                "REJECT",
                f"CURRENT_AUDIT_RESOURCE_BOUND:{compressed_label}.gz",
            ),
        ):
            payload, compressed = _exact_size_canonical_gzip(size)
            gzip_path.write_bytes(compressed)
            record = _gzip_record(gzip_path, payload, compressed)
            cases.append(
                _measure_case(
                    case_id=f"read_gzip_evidence.MAX_COMPRESSED_LOG_BYTES.{suffix}",
                    primitive="_read_gzip_evidence",
                    limit_name="MAX_COMPRESSED_LOG_BYTES",
                    subject="GZIP_COMPRESSED_FILE_BYTES",
                    unit="BYTES",
                    limit_value=compressed_limit,
                    input_value=size,
                    fixture=_fixture(
                        file_bytes=len(compressed), decompressed_bytes=len(payload)
                    ),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(
                        verifier._read_gzip_evidence,
                        root,
                        record,
                        compressed_label,
                        limits["MAX_LOG_BYTES"],
                    ),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

        json_structure_specs: tuple[
            tuple[
                str,
                str,
                str,
                str,
                Callable[[int], tuple[dict[str, Any], dict[str, int]]],
            ],
            ...,
        ] = (
            (
                "MAX_JSON_DEPTH",
                "JSON_MAXIMUM_DEPTH",
                "LEVELS",
                "profile.json.depth",
                _json_depth_fixture,
            ),
            (
                "MAX_JSON_NODES",
                "JSON_NODE_COUNT",
                "NODES",
                "profile.json.nodes",
                _json_node_fixture,
            ),
            (
                "MAX_JSON_STRING_BYTES",
                "JSON_AGGREGATE_STRING_UTF8_BYTES",
                "BYTES",
                "profile.json.strings",
                _json_string_fixture,
            ),
            (
                "MAX_JSON_CONTAINER_ENTRIES",
                "JSON_CONTAINER_ENTRY_COUNT",
                "ENTRIES",
                "profile.json.entries",
                _json_container_fixture,
            ),
        )
        json_errors = {
            "MAX_JSON_DEPTH": "CURRENT_AUDIT_JSON_DEPTH_BOUND",
            "MAX_JSON_NODES": "CURRENT_AUDIT_JSON_NODE_BOUND",
            "MAX_JSON_STRING_BYTES": "CURRENT_AUDIT_JSON_STRING_BYTES_BOUND",
            "MAX_JSON_CONTAINER_ENTRIES": (
                "CURRENT_AUDIT_JSON_CONTAINER_ENTRIES_BOUND"
            ),
        }
        for limit_name, subject, unit, label, factory in json_structure_specs:
            limit = (
                limits[limit_name]
                if limit_name in limits
                else json_structure_limits[limit_name]
            )
            for suffix, size, expected, error_code in (
                ("exact", limit, "ACCEPT", None),
                (
                    "over",
                    limit + 1,
                    "REJECT",
                    f"{json_errors[limit_name]}:{label}",
                ),
            ):
                value, dimensions = factory(size)
                cases.append(
                    _measure_case(
                        case_id=f"json_structure.{limit_name}.{suffix}",
                        primitive="_validate_json_structure",
                        limit_name=limit_name,
                        subject=subject,
                        unit=unit,
                        limit_value=limit,
                        input_value=size,
                        fixture=_fixture(**dimensions),
                        expected_outcome=expected,
                        expected_error_code=error_code,
                        action=partial(verifier._validate_json_structure, value, label),
                        expected_exception=verifier.CurrentAuditError,
                    )
                )

        decompressed_limit = limits["MAX_LOG_BYTES"]
        decompressed_label = "profile.gzip.decompressed"
        for suffix, size, expected, error_code in (
            ("exact", decompressed_limit, "ACCEPT", None),
            (
                "over",
                decompressed_limit + 1,
                "REJECT",
                f"CURRENT_AUDIT_GZIP_RESOURCE_BOUND:{decompressed_label}",
            ),
        ):
            payload = _utf8_payload_exact(size)
            compressed = _deterministic_gzip(payload)
            if len(compressed) > compressed_limit:
                raise ProfileError(
                    "decompressed-boundary gzip fixture exceeds its limit"
                )
            gzip_path.write_bytes(compressed)
            record = _gzip_record(gzip_path, payload, compressed)
            cases.append(
                _measure_case(
                    case_id=f"read_gzip_evidence.MAX_LOG_BYTES.{suffix}",
                    primitive="_read_gzip_evidence",
                    limit_name="MAX_LOG_BYTES",
                    subject="GZIP_DECOMPRESSED_BYTES",
                    unit="BYTES",
                    limit_value=decompressed_limit,
                    input_value=size,
                    fixture=_fixture(
                        file_bytes=len(compressed), decompressed_bytes=len(payload)
                    ),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(
                        verifier._read_gzip_evidence,
                        root,
                        record,
                        decompressed_label,
                        decompressed_limit,
                    ),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

        entry_limit = limits["MAX_ZIP_ENTRY_BYTES"]
        entry_label = "profile.zip.entry"
        for suffix, size, expected, error_code in (
            ("exact", entry_limit, "ACCEPT", None),
            (
                "over",
                entry_limit + 1,
                "REJECT",
                f"CURRENT_AUDIT_ZIP_ENTRY_INVALID:{entry_label}",
            ),
        ):
            archive = _deterministic_zip([size])
            cases.append(
                _measure_case(
                    case_id=f"verify_handoff_zip.MAX_ZIP_ENTRY_BYTES.{suffix}",
                    primitive="_verify_handoff_zip",
                    limit_name="MAX_ZIP_ENTRY_BYTES",
                    subject="ZIP_ENTRY_UNCOMPRESSED_BYTES",
                    unit="BYTES",
                    limit_value=entry_limit,
                    input_value=size,
                    fixture=_fixture(
                        zip_archive_bytes=len(archive),
                        zip_entry_count=1,
                        zip_largest_entry_bytes=size,
                        zip_total_uncompressed_bytes=size,
                    ),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(
                        verifier._verify_handoff_zip, archive, 1, entry_label
                    ),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

        total_limit = limits["MAX_ZIP_TOTAL_BYTES"]
        total_label = "profile.zip.total"
        for suffix, size, expected, error_code in (
            ("exact", total_limit, "ACCEPT", None),
            (
                "over",
                total_limit + 1,
                "REJECT",
                f"CURRENT_AUDIT_ZIP_INVENTORY_INVALID:{total_label}",
            ),
        ):
            entry_sizes = _split_zip_total(size, entry_limit)
            archive = _deterministic_zip(entry_sizes)
            cases.append(
                _measure_case(
                    case_id=f"verify_handoff_zip.MAX_ZIP_TOTAL_BYTES.{suffix}",
                    primitive="_verify_handoff_zip",
                    limit_name="MAX_ZIP_TOTAL_BYTES",
                    subject="ZIP_TOTAL_UNCOMPRESSED_BYTES",
                    unit="BYTES",
                    limit_value=total_limit,
                    input_value=size,
                    fixture=_fixture(
                        zip_archive_bytes=len(archive),
                        zip_entry_count=len(entry_sizes),
                        zip_largest_entry_bytes=max(entry_sizes),
                        zip_total_uncompressed_bytes=sum(entry_sizes),
                    ),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(
                        verifier._verify_handoff_zip,
                        archive,
                        len(entry_sizes),
                        total_label,
                    ),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

        git_limit = limits["MAX_GIT_BYTES"]
        for stream in ("stdout", "stderr"):
            for suffix, size, expected, error_code in (
                ("exact", git_limit, "ACCEPT", None),
                (
                    "over",
                    git_limit + 1,
                    "REJECT",
                    "CURRENT_AUDIT_GIT_OUTPUT_BOUND",
                ),
            ):
                fake_bin = root / f"fake-bin-{stream}-{suffix}"
                fake_bin.mkdir(mode=0o700)
                fake_bin.chmod(0o700)
                fake_git = _write_fake_git(
                    fake_bin, size=size, stream_name=stream
                ).resolve()
                fixture_identity = _private_fixture_identity(fake_git)
                fixture_payload = fake_git.read_bytes()
                prior_git = getattr(verifier, "GIT_EXECUTABLE")
                prior_trust = getattr(verifier, "_verify_trusted_executable")

                def verify_profile_fixture(path: str, label: str) -> None:
                    if path != str(fake_git) or label != "git":
                        prior_trust(path, label)
                        return
                    if (
                        _private_fixture_identity(fake_git) != fixture_identity
                        or fake_git.read_bytes() != fixture_payload
                    ):
                        raise verifier.CurrentAuditError(
                            "CURRENT_AUDIT_PROFILE_GIT_FIXTURE_CHANGED"
                        )

                setattr(verifier, "GIT_EXECUTABLE", str(fake_git))
                setattr(
                    verifier,
                    "_verify_trusted_executable",
                    verify_profile_fixture,
                )
                try:
                    cases.append(
                        _measure_case(
                            case_id=f"git.MAX_GIT_BYTES.{stream}.{suffix}",
                            primitive="_git",
                            limit_name="MAX_GIT_BYTES",
                            subject=f"GIT_{stream.upper()}_BYTES",
                            unit="BYTES",
                            limit_value=git_limit,
                            input_value=size,
                            fixture=_fixture(
                                git_stdout_bytes=size if stream == "stdout" else 0,
                                git_stderr_bytes=size if stream == "stderr" else 0,
                            ),
                            expected_outcome=expected,
                            expected_error_code=error_code,
                            action=partial(verifier._git, root, "resource-profile"),
                            expected_exception=verifier.CurrentAuditError,
                        )
                    )
                finally:
                    setattr(verifier, "GIT_EXECUTABLE", prior_git)
                    setattr(verifier, "_verify_trusted_executable", prior_trust)
                if (
                    _private_fixture_identity(fake_git) != fixture_identity
                    or fake_git.read_bytes() != fixture_payload
                ):
                    raise ProfileError("fake-git fixture changed during profiling")

        hygiene_limit = limits["MAX_HYGIENE_TOTAL_BYTES"]
        for suffix, size, expected, error_code in (
            ("exact", hygiene_limit, "ACCEPT", None),
            (
                "over",
                hygiene_limit + 1,
                "REJECT",
                "CURRENT_AUDIT_HYGIENE_AGGREGATE_BOUND",
            ),
        ):
            current = size - 1
            increment = 1
            cases.append(
                _measure_case(
                    case_id=f"hygiene.MAX_HYGIENE_TOTAL_BYTES.{suffix}",
                    primitive="_bounded_hygiene_total",
                    limit_name="MAX_HYGIENE_TOTAL_BYTES",
                    subject="HYGIENE_TOTAL_BYTES",
                    unit="BYTES",
                    limit_value=hygiene_limit,
                    input_value=size,
                    fixture=_fixture(
                        hygiene_total_bytes=size,
                        hygiene_current_bytes=current,
                        hygiene_increment_bytes=increment,
                    ),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(verifier._bounded_hygiene_total, current, increment),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

        revocation_file_limit = limits["MAX_REVOCATION_CAUSE_FILE_BYTES"]
        for suffix, size, expected, error_code in (
            ("exact", revocation_file_limit, "ACCEPT", None),
            (
                "over",
                revocation_file_limit + 1,
                "REJECT",
                "CURRENT_AUDIT_REVOCATION_CAUSE_FILE_BOUND",
            ),
        ):
            cases.append(
                _measure_case(
                    case_id=(
                        f"revocation_cause.MAX_REVOCATION_CAUSE_FILE_BYTES.{suffix}"
                    ),
                    primitive="_bounded_revocation_cause_total",
                    limit_name="MAX_REVOCATION_CAUSE_FILE_BYTES",
                    subject="REVOCATION_CAUSE_FILE_BYTES",
                    unit="BYTES",
                    limit_value=revocation_file_limit,
                    input_value=size,
                    fixture=_fixture(
                        revocation_cause_total_bytes=size,
                        revocation_cause_current_bytes=0,
                        revocation_cause_file_bytes=size,
                    ),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(verifier._bounded_revocation_cause_total, 0, size),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

        revocation_total_limit = limits["MAX_REVOCATION_CAUSE_TOTAL_BYTES"]
        for suffix, size, expected, error_code in (
            ("exact", revocation_total_limit, "ACCEPT", None),
            (
                "over",
                revocation_total_limit + 1,
                "REJECT",
                "CURRENT_AUDIT_REVOCATION_CAUSE_TOTAL_BOUND",
            ),
        ):
            current = size - 1
            increment = 1
            cases.append(
                _measure_case(
                    case_id=(
                        f"revocation_cause.MAX_REVOCATION_CAUSE_TOTAL_BYTES.{suffix}"
                    ),
                    primitive="_bounded_revocation_cause_total",
                    limit_name="MAX_REVOCATION_CAUSE_TOTAL_BYTES",
                    subject="REVOCATION_CAUSE_TOTAL_BYTES",
                    unit="BYTES",
                    limit_value=revocation_total_limit,
                    input_value=size,
                    fixture=_fixture(
                        revocation_cause_total_bytes=size,
                        revocation_cause_current_bytes=current,
                        revocation_cause_file_bytes=increment,
                    ),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(
                        verifier._bounded_revocation_cause_total,
                        current,
                        increment,
                    ),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

        protocol_path_limit = limits["MAX_PROTOCOL_PATH_BYTES"]
        protocol_path_label = "profile.protocol.path"
        for suffix, size, expected, error_code in (
            ("exact", protocol_path_limit, "ACCEPT", None),
            (
                "over",
                protocol_path_limit + 1,
                "REJECT",
                f"CURRENT_AUDIT_PROTOCOL_PATH_BOUND:{protocol_path_label}",
            ),
        ):
            protocol_path = _protocol_path_fixture(size)
            cases.append(
                _measure_case(
                    case_id=f"protocol_path.MAX_PROTOCOL_PATH_BYTES.{suffix}",
                    primitive="_require_protocol_path",
                    limit_name="MAX_PROTOCOL_PATH_BYTES",
                    subject="PROTOCOL_PATH_UTF8_BYTES",
                    unit="BYTES",
                    limit_value=protocol_path_limit,
                    input_value=size,
                    fixture=_fixture(protocol_path_bytes=size),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(
                        verifier._require_protocol_path,
                        protocol_path,
                        protocol_path_label,
                    ),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

        verifier_output_limit = limits["MAX_VERIFIER_OUTPUT_BYTES"]
        verifier_output_label = "profile.verifier.output"
        for suffix, size, expected, error_code in (
            ("exact", verifier_output_limit, "ACCEPT", None),
            (
                "over",
                verifier_output_limit + 1,
                "REJECT",
                f"CURRENT_AUDIT_VERIFIER_OUTPUT_BOUND:{verifier_output_label}",
            ),
        ):
            verifier_output = _utf8_payload_exact(size)
            cases.append(
                _measure_case(
                    case_id=(f"verifier_output.MAX_VERIFIER_OUTPUT_BYTES.{suffix}"),
                    primitive="_require_verifier_output_bound",
                    limit_name="MAX_VERIFIER_OUTPUT_BYTES",
                    subject="REGISTERED_VERIFIER_OUTPUT_BYTES",
                    unit="BYTES",
                    limit_value=verifier_output_limit,
                    input_value=size,
                    fixture=_fixture(verifier_output_bytes=size),
                    expected_outcome=expected,
                    expected_error_code=error_code,
                    action=partial(
                        verifier._require_verifier_output_bound,
                        verifier_output,
                        verifier_output_label,
                    ),
                    expected_exception=verifier.CurrentAuditError,
                )
            )

    environment = _tool_environment(verifier)
    completed_at_utc = _utc_now()
    profile = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "generated_at_utc": completed_at_utc,
        "verifier": {
            "path": _display_path(verifier_path),
            "sha256": _sha256(verifier_payload),
            "bytes": len(verifier_payload),
            "identity": f"sha256:{_sha256(verifier_payload)}/{len(verifier_payload)}",
        },
        "environment": environment,
        "interpretation": {
            "timings": {
                "classification": TIMING_CLASSIFICATION,
                "cross_run_comparable": False,
                "latency_acceptance_claim": False,
                "statement": TIMING_STATEMENT,
            },
            "timeout": {
                "classification": TIMEOUT_CLASSIFICATION,
                "included_in_profile_cases": False,
                "profiled_as_resource_maximum": False,
                "statement": TIMEOUT_STATEMENT,
            },
        },
        "configuration": {
            "samples_per_case": SAMPLES_PER_CASE,
            "limits_bytes": limits,
            "json_structure_limits": json_structure_limits,
            "git_fixture_seam": dict(GIT_FIXTURE_SEAM),
        },
        "cases": cases,
        "overall_pass": all(case["pass"] for case in cases),
    }
    validate_profile(profile, verifier_payload=verifier_payload)
    return profile


def _require_exact_keys(
    value: object, expected: set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProfileError(f"{label} has invalid keys")
    return value


def _require_string(value: object, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise ProfileError(f"{label} must be a string")
    return value


def _require_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ProfileError(f"{label} must be an integer >= {minimum}")
    return value


def _expected_case_specs(
    limits: Mapping[str, int],
) -> list[tuple[str, str, str, str, str, int, int, str, str | None]]:
    specs: list[tuple[str, str, str, str, str, int, int, str, str | None]] = []

    def pair(
        stem: str,
        primitive: str,
        limit_name: str,
        subject: str,
        exact_error: str,
        unit: str = "BYTES",
    ) -> None:
        limit = limits[limit_name]
        specs.extend(
            [
                (
                    f"{stem}.exact",
                    primitive,
                    limit_name,
                    subject,
                    unit,
                    limit,
                    limit,
                    "ACCEPT",
                    None,
                ),
                (
                    f"{stem}.over",
                    primitive,
                    limit_name,
                    subject,
                    unit,
                    limit,
                    limit + 1,
                    "REJECT",
                    exact_error,
                ),
            ]
        )

    pair(
        "load_json.MAX_JSON_BYTES",
        "_load_json",
        "MAX_JSON_BYTES",
        "JSON_FILE_BYTES",
        "CURRENT_AUDIT_RESOURCE_BOUND:profile.json.MAX_JSON_BYTES",
    )
    pair(
        "load_json.MAX_REQUIREMENTS_BYTES",
        "_load_json",
        "MAX_REQUIREMENTS_BYTES",
        "JSON_FILE_BYTES",
        "CURRENT_AUDIT_RESOURCE_BOUND:profile.json.MAX_REQUIREMENTS_BYTES",
    )
    pair(
        "read_gzip_evidence.MAX_COMPRESSED_LOG_BYTES",
        "_read_gzip_evidence",
        "MAX_COMPRESSED_LOG_BYTES",
        "GZIP_COMPRESSED_FILE_BYTES",
        "CURRENT_AUDIT_RESOURCE_BOUND:profile.gzip.compressed.gz",
    )
    pair(
        "json_structure.MAX_JSON_DEPTH",
        "_validate_json_structure",
        "MAX_JSON_DEPTH",
        "JSON_MAXIMUM_DEPTH",
        "CURRENT_AUDIT_JSON_DEPTH_BOUND:profile.json.depth",
        "LEVELS",
    )
    pair(
        "json_structure.MAX_JSON_NODES",
        "_validate_json_structure",
        "MAX_JSON_NODES",
        "JSON_NODE_COUNT",
        "CURRENT_AUDIT_JSON_NODE_BOUND:profile.json.nodes",
        "NODES",
    )
    pair(
        "json_structure.MAX_JSON_STRING_BYTES",
        "_validate_json_structure",
        "MAX_JSON_STRING_BYTES",
        "JSON_AGGREGATE_STRING_UTF8_BYTES",
        "CURRENT_AUDIT_JSON_STRING_BYTES_BOUND:profile.json.strings",
    )
    pair(
        "json_structure.MAX_JSON_CONTAINER_ENTRIES",
        "_validate_json_structure",
        "MAX_JSON_CONTAINER_ENTRIES",
        "JSON_CONTAINER_ENTRY_COUNT",
        "CURRENT_AUDIT_JSON_CONTAINER_ENTRIES_BOUND:profile.json.entries",
        "ENTRIES",
    )
    pair(
        "read_gzip_evidence.MAX_LOG_BYTES",
        "_read_gzip_evidence",
        "MAX_LOG_BYTES",
        "GZIP_DECOMPRESSED_BYTES",
        "CURRENT_AUDIT_GZIP_RESOURCE_BOUND:profile.gzip.decompressed",
    )
    pair(
        "verify_handoff_zip.MAX_ZIP_ENTRY_BYTES",
        "_verify_handoff_zip",
        "MAX_ZIP_ENTRY_BYTES",
        "ZIP_ENTRY_UNCOMPRESSED_BYTES",
        "CURRENT_AUDIT_ZIP_ENTRY_INVALID:profile.zip.entry",
    )
    pair(
        "verify_handoff_zip.MAX_ZIP_TOTAL_BYTES",
        "_verify_handoff_zip",
        "MAX_ZIP_TOTAL_BYTES",
        "ZIP_TOTAL_UNCOMPRESSED_BYTES",
        "CURRENT_AUDIT_ZIP_INVENTORY_INVALID:profile.zip.total",
    )
    for stream in ("stdout", "stderr"):
        pair(
            f"git.MAX_GIT_BYTES.{stream}",
            "_git",
            "MAX_GIT_BYTES",
            f"GIT_{stream.upper()}_BYTES",
            "CURRENT_AUDIT_GIT_OUTPUT_BOUND",
        )
    pair(
        "hygiene.MAX_HYGIENE_TOTAL_BYTES",
        "_bounded_hygiene_total",
        "MAX_HYGIENE_TOTAL_BYTES",
        "HYGIENE_TOTAL_BYTES",
        "CURRENT_AUDIT_HYGIENE_AGGREGATE_BOUND",
    )
    pair(
        "revocation_cause.MAX_REVOCATION_CAUSE_FILE_BYTES",
        "_bounded_revocation_cause_total",
        "MAX_REVOCATION_CAUSE_FILE_BYTES",
        "REVOCATION_CAUSE_FILE_BYTES",
        "CURRENT_AUDIT_REVOCATION_CAUSE_FILE_BOUND",
    )
    pair(
        "revocation_cause.MAX_REVOCATION_CAUSE_TOTAL_BYTES",
        "_bounded_revocation_cause_total",
        "MAX_REVOCATION_CAUSE_TOTAL_BYTES",
        "REVOCATION_CAUSE_TOTAL_BYTES",
        "CURRENT_AUDIT_REVOCATION_CAUSE_TOTAL_BOUND",
    )
    pair(
        "protocol_path.MAX_PROTOCOL_PATH_BYTES",
        "_require_protocol_path",
        "MAX_PROTOCOL_PATH_BYTES",
        "PROTOCOL_PATH_UTF8_BYTES",
        "CURRENT_AUDIT_PROTOCOL_PATH_BOUND:profile.protocol.path",
    )
    pair(
        "verifier_output.MAX_VERIFIER_OUTPUT_BYTES",
        "_require_verifier_output_bound",
        "MAX_VERIFIER_OUTPUT_BYTES",
        "REGISTERED_VERIFIER_OUTPUT_BYTES",
        "CURRENT_AUDIT_VERIFIER_OUTPUT_BOUND:profile.verifier.output",
    )
    return specs


def _validate_fixture(
    fixture: object,
    *,
    case_index: int,
    subject: str,
    input_value: int,
    limits: Mapping[str, int],
) -> None:
    label = f"cases[{case_index}].fixture"
    record = _require_exact_keys(fixture, set(_empty_fixture()), label)
    values: dict[str, int | None] = {}
    for key, value in record.items():
        if value is None:
            values[key] = None
        else:
            values[key] = _require_int(value, f"{label}.{key}")

    expected_non_null: set[str]
    if subject == "JSON_FILE_BYTES":
        expected_non_null = {"file_bytes"}
        if values["file_bytes"] != input_value:
            raise ProfileError(f"{label}.file_bytes contradicts input_value")
    elif subject == "GZIP_COMPRESSED_FILE_BYTES":
        expected_non_null = {"file_bytes", "decompressed_bytes"}
        deflate_bytes = input_value - 18
        block_count = max(1, (deflate_bytes + 65_539) // 65_540)
        expected_payload_bytes = deflate_bytes - (5 * block_count)
        if (
            values["file_bytes"] != input_value
            or values["decompressed_bytes"] != expected_payload_bytes
            or expected_payload_bytes < 0
            or expected_payload_bytes > limits["MAX_LOG_BYTES"]
        ):
            raise ProfileError(f"{label} contradicts compressed fixture dimensions")
    elif subject == "GZIP_DECOMPRESSED_BYTES":
        expected_non_null = {"file_bytes", "decompressed_bytes"}
        file_bytes = values["file_bytes"]
        if (
            file_bytes is None
            or file_bytes <= 0
            or file_bytes > limits["MAX_COMPRESSED_LOG_BYTES"]
            or values["decompressed_bytes"] != input_value
        ):
            raise ProfileError(f"{label} contradicts decompressed fixture dimensions")
    elif subject == "ZIP_ENTRY_UNCOMPRESSED_BYTES":
        expected_non_null = {
            "zip_archive_bytes",
            "zip_entry_count",
            "zip_largest_entry_bytes",
            "zip_total_uncompressed_bytes",
        }
        if (
            values["zip_archive_bytes"] is None
            or values["zip_archive_bytes"] <= 0
            or values["zip_entry_count"] != 1
            or values["zip_largest_entry_bytes"] != input_value
            or values["zip_total_uncompressed_bytes"] != input_value
            or input_value > limits["MAX_ZIP_TOTAL_BYTES"]
        ):
            raise ProfileError(f"{label} contradicts single-entry ZIP dimensions")
    elif subject == "ZIP_TOTAL_UNCOMPRESSED_BYTES":
        expected_non_null = {
            "zip_archive_bytes",
            "zip_entry_count",
            "zip_largest_entry_bytes",
            "zip_total_uncompressed_bytes",
        }
        entry_count = values["zip_entry_count"]
        largest = values["zip_largest_entry_bytes"]
        expected_count = (input_value + limits["MAX_ZIP_ENTRY_BYTES"] - 1) // limits[
            "MAX_ZIP_ENTRY_BYTES"
        ]
        if (
            values["zip_archive_bytes"] is None
            or values["zip_archive_bytes"] <= 0
            or entry_count != expected_count
            or largest != min(input_value, limits["MAX_ZIP_ENTRY_BYTES"])
            or values["zip_total_uncompressed_bytes"] != input_value
            or largest is None
            or largest > limits["MAX_ZIP_ENTRY_BYTES"]
        ):
            raise ProfileError(f"{label} contradicts aggregate ZIP dimensions")
    elif subject in {"GIT_STDOUT_BYTES", "GIT_STDERR_BYTES"}:
        expected_non_null = {"git_stdout_bytes", "git_stderr_bytes"}
        expected_stdout = input_value if subject == "GIT_STDOUT_BYTES" else 0
        expected_stderr = input_value if subject == "GIT_STDERR_BYTES" else 0
        if (
            values["git_stdout_bytes"] != expected_stdout
            or values["git_stderr_bytes"] != expected_stderr
        ):
            raise ProfileError(f"{label} contradicts bounded Git stream dimensions")
    elif subject == "HYGIENE_TOTAL_BYTES":
        expected_non_null = {
            "hygiene_total_bytes",
            "hygiene_current_bytes",
            "hygiene_increment_bytes",
        }
        current = values["hygiene_current_bytes"]
        increment = values["hygiene_increment_bytes"]
        if (
            values["hygiene_total_bytes"] != input_value
            or current is None
            or increment is None
            or current != input_value - 1
            or increment != 1
        ):
            raise ProfileError(f"{label} contradicts hygiene aggregate dimensions")
    elif subject == "REVOCATION_CAUSE_FILE_BYTES":
        expected_non_null = {
            "revocation_cause_total_bytes",
            "revocation_cause_current_bytes",
            "revocation_cause_file_bytes",
        }
        if (
            values["revocation_cause_total_bytes"] != input_value
            or values["revocation_cause_current_bytes"] != 0
            or values["revocation_cause_file_bytes"] != input_value
        ):
            raise ProfileError(f"{label} contradicts revocation cause-file dimensions")
    elif subject == "REVOCATION_CAUSE_TOTAL_BYTES":
        expected_non_null = {
            "revocation_cause_total_bytes",
            "revocation_cause_current_bytes",
            "revocation_cause_file_bytes",
        }
        if (
            values["revocation_cause_total_bytes"] != input_value
            or values["revocation_cause_current_bytes"] != input_value - 1
            or values["revocation_cause_file_bytes"] != 1
        ):
            raise ProfileError(f"{label} contradicts revocation cause-total dimensions")
    elif subject == "PROTOCOL_PATH_UTF8_BYTES":
        expected_non_null = {"protocol_path_bytes"}
        if values["protocol_path_bytes"] != input_value:
            raise ProfileError(f"{label} contradicts protocol-path dimensions")
    elif subject == "REGISTERED_VERIFIER_OUTPUT_BYTES":
        expected_non_null = {"verifier_output_bytes"}
        if values["verifier_output_bytes"] != input_value:
            raise ProfileError(f"{label} contradicts verifier-output dimensions")
    elif subject in {
        "JSON_MAXIMUM_DEPTH",
        "JSON_NODE_COUNT",
        "JSON_AGGREGATE_STRING_UTF8_BYTES",
        "JSON_CONTAINER_ENTRY_COUNT",
    }:
        expected_non_null = {
            "json_depth",
            "json_nodes",
            "json_string_bytes",
            "json_container_entries",
        }
        if subject == "JSON_MAXIMUM_DEPTH":
            expected_dimensions = {
                "json_depth": input_value,
                "json_nodes": input_value + 1,
                "json_string_bytes": 0,
                "json_container_entries": input_value - 1,
            }
        elif subject == "JSON_NODE_COUNT":
            exact = input_value == limits["MAX_JSON_NODES"]
            members = (input_value - (2 if exact else 1)) // 2
            expected_dimensions = {
                "json_depth": 3 if exact else 2,
                "json_nodes": input_value,
                "json_string_bytes": 6 * members,
                "json_container_entries": limits["MAX_JSON_CONTAINER_ENTRIES"],
            }
        elif subject == "JSON_AGGREGATE_STRING_UTF8_BYTES":
            expected_dimensions = {
                "json_depth": 2,
                "json_nodes": 3,
                "json_string_bytes": input_value,
                "json_container_entries": 1,
            }
        else:
            expected_dimensions = {
                "json_depth": 3,
                "json_nodes": input_value + 2,
                "json_string_bytes": 0,
                "json_container_entries": input_value,
            }
        if any(
            values[key] != expected for key, expected in expected_dimensions.items()
        ):
            raise ProfileError(f"{label} contradicts JSON structural dimensions")
    else:  # pragma: no cover - every subject comes from the fixed specification.
        raise ProfileError(f"{label} has an unknown subject")

    actual_non_null = {key for key, value in values.items() if value is not None}
    if actual_non_null != expected_non_null:
        raise ProfileError(f"{label} has dimensions unrelated to its subject")


def validate_profile(profile: object, *, verifier_payload: bytes | None = None) -> None:
    """Validate the exact evidence schema and all internal boundary relations."""

    root = _require_exact_keys(
        profile,
        {
            "schema_version",
            "profile_id",
            "generated_at_utc",
            "verifier",
            "environment",
            "interpretation",
            "configuration",
            "cases",
            "overall_pass",
        },
        "profile",
    )
    if root["schema_version"] != SCHEMA_VERSION or root["profile_id"] != PROFILE_ID:
        raise ProfileError("profile identity is invalid")
    generated = _require_string(root["generated_at_utc"], "generated_at_utc")
    if RFC3339_UTC.fullmatch(generated) is None:
        raise ProfileError("generated_at_utc is not RFC3339 UTC")
    try:
        dt.datetime.strptime(generated, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ProfileError("generated_at_utc is not a valid calendar time") from error

    verifier = _require_exact_keys(
        root["verifier"], {"path", "sha256", "bytes", "identity"}, "verifier"
    )
    _require_string(verifier["path"], "verifier.path")
    digest = _require_string(verifier["sha256"], "verifier.sha256")
    if HEX64.fullmatch(digest) is None:
        raise ProfileError("verifier.sha256 is invalid")
    verifier_bytes = _require_int(verifier["bytes"], "verifier.bytes", minimum=1)
    if verifier["identity"] != f"sha256:{digest}/{verifier_bytes}":
        raise ProfileError("verifier.identity contradicts digest or size")
    if verifier_payload is not None and (
        len(verifier_payload) != verifier_bytes or _sha256(verifier_payload) != digest
    ):
        raise ProfileError("verifier record contradicts the executed snapshot")

    environment = _require_exact_keys(
        root["environment"],
        {"platform", "hardware", "python", "tools"},
        "environment",
    )
    platform_record = _require_exact_keys(
        environment["platform"],
        {"system", "release", "machine"},
        "environment.platform",
    )
    hardware_record = _require_exact_keys(
        environment["hardware"],
        {"logical_cpu_count", "physical_memory_bytes", "physical_memory_source"},
        "environment.hardware",
    )
    python_record = _require_exact_keys(
        environment["python"], {"implementation", "version"}, "environment.python"
    )
    tools_record = _require_exact_keys(
        environment["tools"],
        {"git", "git_path", "zlib_compile", "zlib_runtime"},
        "environment.tools",
    )
    for label, record in (
        ("environment.platform", platform_record),
        ("environment.python", python_record),
        ("environment.tools", tools_record),
    ):
        for key, value in record.items():
            _require_string(value, f"{label}.{key}")
    if tools_record["git_path"] != EXPECTED_GIT_EXECUTABLE:
        raise ProfileError("environment.tools.git_path is invalid")
    _require_int(
        hardware_record["logical_cpu_count"],
        "environment.hardware.logical_cpu_count",
        minimum=1,
    )
    _require_int(
        hardware_record["physical_memory_bytes"],
        "environment.hardware.physical_memory_bytes",
        minimum=1,
    )
    _require_string(
        hardware_record["physical_memory_source"],
        "environment.hardware.physical_memory_source",
    )

    interpretation = _require_exact_keys(
        root["interpretation"], {"timings", "timeout"}, "interpretation"
    )
    timings = _require_exact_keys(
        interpretation["timings"],
        {
            "classification",
            "cross_run_comparable",
            "latency_acceptance_claim",
            "statement",
        },
        "interpretation.timings",
    )
    expected_timings = {
        "classification": TIMING_CLASSIFICATION,
        "cross_run_comparable": False,
        "latency_acceptance_claim": False,
        "statement": TIMING_STATEMENT,
    }
    if any(
        type(timings[key]) is not type(value) or timings[key] != value
        for key, value in expected_timings.items()
    ):
        raise ProfileError("interpretation.timings is invalid")
    timeout = _require_exact_keys(
        interpretation["timeout"],
        {
            "classification",
            "included_in_profile_cases",
            "profiled_as_resource_maximum",
            "statement",
        },
        "interpretation.timeout",
    )
    expected_timeout = {
        "classification": TIMEOUT_CLASSIFICATION,
        "included_in_profile_cases": False,
        "profiled_as_resource_maximum": False,
        "statement": TIMEOUT_STATEMENT,
    }
    if any(
        type(timeout[key]) is not type(value) or timeout[key] != value
        for key, value in expected_timeout.items()
    ):
        raise ProfileError("interpretation.timeout is invalid")

    configuration = _require_exact_keys(
        root["configuration"],
        {
            "samples_per_case",
            "limits_bytes",
            "json_structure_limits",
            "git_fixture_seam",
        },
        "configuration",
    )
    if (
        type(configuration["samples_per_case"]) is not int
        or configuration["samples_per_case"] != SAMPLES_PER_CASE
    ):
        raise ProfileError("configuration.samples_per_case is invalid")
    limits = _require_exact_keys(
        configuration["limits_bytes"], set(LIMIT_NAMES), "configuration.limits_bytes"
    )
    typed_limits = {
        name: _require_int(
            limits[name], f"configuration.limits_bytes.{name}", minimum=1
        )
        for name in LIMIT_NAMES
    }
    if typed_limits != EXPECTED_LIMITS_BYTES:
        raise ProfileError("configuration limits are unsupported")
    if verifier_payload is not None and typed_limits != _verifier_limit_values(
        verifier_payload
    ):
        raise ProfileError("configuration limits contradict the verifier snapshot")
    if typed_limits["MAX_ZIP_TOTAL_BYTES"] <= typed_limits["MAX_ZIP_ENTRY_BYTES"]:
        raise ProfileError("configuration ZIP limits are contradictory")
    json_limits = _require_exact_keys(
        configuration["json_structure_limits"],
        set(JSON_STRUCTURE_LIMIT_NAMES),
        "configuration.json_structure_limits",
    )
    typed_json_limits = {
        name: _require_int(
            json_limits[name],
            f"configuration.json_structure_limits.{name}",
            minimum=1,
        )
        for name in JSON_STRUCTURE_LIMIT_NAMES
    }
    if typed_json_limits != EXPECTED_JSON_STRUCTURE_LIMITS:
        raise ProfileError("configuration JSON structural limits are unsupported")
    if (
        verifier_payload is not None
        and typed_json_limits != _verifier_json_structure_values(verifier_payload)
    ):
        raise ProfileError("configuration JSON limits contradict the verifier snapshot")
    seam = _require_exact_keys(
        configuration["git_fixture_seam"],
        set(GIT_FIXTURE_SEAM),
        "configuration.git_fixture_seam",
    )
    if any(
        type(seam[key]) is not type(value) or seam[key] != value
        for key, value in GIT_FIXTURE_SEAM.items()
    ):
        raise ProfileError("configuration.git_fixture_seam is invalid")

    cases = root["cases"]
    if not isinstance(cases, list):
        raise ProfileError("cases must be an array")
    all_limits = {**typed_limits, **typed_json_limits}
    specs = _expected_case_specs(all_limits)
    if len(cases) != len(specs):
        raise ProfileError("cases has the wrong length")
    case_keys = {
        "id",
        "primitive",
        "limit_name",
        "subject",
        "unit",
        "limit_value",
        "input_value",
        "fixture",
        "expected_outcome",
        "observed_outcome",
        "expected_error_code",
        "observed_error_codes",
        "accepted_samples",
        "rejected_samples",
        "elapsed_ns",
        "pass",
    }
    for index, (raw_case, spec) in enumerate(zip(cases, specs, strict=True)):
        case = _require_exact_keys(raw_case, case_keys, f"cases[{index}]")
        (
            expected_id,
            expected_primitive,
            expected_limit_name,
            expected_subject,
            expected_unit,
            expected_limit,
            expected_input,
            expected_outcome,
            expected_error,
        ) = spec
        expected_values = {
            "id": expected_id,
            "primitive": expected_primitive,
            "limit_name": expected_limit_name,
            "subject": expected_subject,
            "unit": expected_unit,
            "limit_value": expected_limit,
            "input_value": expected_input,
            "expected_outcome": expected_outcome,
            "expected_error_code": expected_error,
        }
        for key, expected_value in expected_values.items():
            if (
                type(case[key]) is not type(expected_value)
                or case[key] != expected_value
            ):
                raise ProfileError(f"cases[{index}].{key} is invalid")
        _validate_fixture(
            case["fixture"],
            case_index=index,
            subject=expected_subject,
            input_value=expected_input,
            limits=all_limits,
        )

        observed = case["observed_outcome"]
        if observed not in {"ACCEPT", "REJECT", "MIXED"}:
            raise ProfileError(f"cases[{index}].observed_outcome is invalid")
        accepted = _require_int(
            case["accepted_samples"], f"cases[{index}].accepted_samples"
        )
        rejected = _require_int(
            case["rejected_samples"], f"cases[{index}].rejected_samples"
        )
        if accepted + rejected != SAMPLES_PER_CASE:
            raise ProfileError(f"cases[{index}] sample counts are invalid")
        derived_outcome = (
            "ACCEPT"
            if accepted == SAMPLES_PER_CASE
            else "REJECT"
            if rejected == SAMPLES_PER_CASE
            else "MIXED"
        )
        if observed != derived_outcome:
            raise ProfileError(f"cases[{index}].observed_outcome contradicts counts")
        error_codes = case["observed_error_codes"]
        if not isinstance(error_codes, list) or any(
            not isinstance(item, str) or not item for item in error_codes
        ):
            raise ProfileError(f"cases[{index}].observed_error_codes is invalid")
        if error_codes != sorted(set(error_codes)):
            raise ProfileError(f"cases[{index}].observed_error_codes is not canonical")
        if rejected == 0 and error_codes:
            raise ProfileError(f"cases[{index}] records errors without rejections")
        if rejected > 0 and not error_codes:
            raise ProfileError(f"cases[{index}] omits rejection errors")

        elapsed = _require_exact_keys(
            case["elapsed_ns"],
            {"samples", "min", "median", "max"},
            f"cases[{index}].elapsed_ns",
        )
        samples = elapsed["samples"]
        if not isinstance(samples, list) or len(samples) != SAMPLES_PER_CASE:
            raise ProfileError(f"cases[{index}].elapsed_ns.samples is invalid")
        typed_samples = [
            _require_int(value, f"cases[{index}].elapsed_ns.samples", minimum=0)
            for value in samples
        ]
        ordered = sorted(typed_samples)
        if (
            type(elapsed["min"]) is not int
            or type(elapsed["median"]) is not int
            or type(elapsed["max"]) is not int
            or elapsed["min"] != ordered[0]
            or elapsed["median"] != ordered[len(ordered) // 2]
            or elapsed["max"] != ordered[-1]
        ):
            raise ProfileError(f"cases[{index}].elapsed_ns distribution is invalid")
        expected_pass = observed == expected_outcome
        if expected_outcome == "ACCEPT":
            expected_pass = expected_pass and not error_codes
        else:
            expected_pass = expected_pass and error_codes == [expected_error]
        if type(case["pass"]) is not bool or case["pass"] != expected_pass:
            raise ProfileError(f"cases[{index}].pass is invalid")

    expected_overall = all(case["pass"] is True for case in cases)
    if (
        type(root["overall_pass"]) is not bool
        or root["overall_pass"] != expected_overall
    ):
        raise ProfileError("overall_pass contradicts cases")


def render_profile(profile: object) -> bytes:
    validate_profile(profile)
    return (json.dumps(profile, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _normalize_trusted_system_alias(path: Path) -> Path:
    """Resolve only a root-controlled leading POSIX alias such as macOS /var."""

    parts = path.parts
    if len(parts) < 2:
        return path
    leading = Path(os.sep) / parts[1]
    try:
        metadata = leading.lstat()
        root_metadata = Path(os.sep).stat()
    except OSError as error:
        raise ProfileError("cannot inspect the output path root") from error
    if not stat.S_ISLNK(metadata.st_mode):
        return path
    if (
        metadata.st_uid != 0
        or root_metadata.st_uid != 0
        or root_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ProfileError("output path uses an untrusted leading symlink")
    try:
        target = leading.resolve(strict=True)
    except OSError as error:
        raise ProfileError("cannot resolve a trusted leading output alias") from error
    return target.joinpath(*parts[2:])


def _open_output_parent(path: Path, *, create: bool) -> tuple[Path, int]:
    """Open an absolute output parent through a stable no-follow dirfd walk."""

    if (
        os.name != "posix"
        or getattr(os, "O_DIRECTORY", None) is None
        or getattr(os, "O_NOFOLLOW", None) is None
        or os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or os.rename not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
    ):
        raise ProfileError("atomic output requires POSIX no-follow dirfd support")
    absolute = _normalize_trusted_system_alias(Path(os.path.abspath(path)))
    if not absolute.name or absolute.parent == absolute:
        raise ProfileError("atomic output path is invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(os.sep, flags)
        for component in absolute.parent.parts[1:]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                created = False
                try:
                    os.mkdir(component, mode=0o755, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                if created:
                    os.fsync(descriptor)
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise ProfileError("atomic output parent is not a directory")
        return absolute, descriptor
    except BaseException as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if isinstance(error, ProfileError):
            raise
        raise ProfileError("atomic output parent traversal failed") from error


def _rename_atomic(name: str, destination: str, directory_descriptor: int) -> None:
    os.rename(
        name,
        destination,
        src_dir_fd=directory_descriptor,
        dst_dir_fd=directory_descriptor,
    )


def atomic_write(path: Path, payload: bytes) -> None:
    """Durably replace ``path`` through one stable no-follow parent dirfd."""

    path, directory_descriptor = _open_output_parent(path, create=True)
    parent_identity = os.fstat(directory_descriptor)
    temporary_name: str | None = None
    file_descriptor: int | None = None
    try:
        for _ in range(100):
            candidate = f".{path.name}.{secrets.token_hex(16)}.tmp"
            try:
                file_descriptor = os.open(
                    candidate,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if file_descriptor is None or temporary_name is None:
            raise ProfileError("cannot allocate an atomic output sibling")
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            try:
                written = os.write(file_descriptor, view[offset:])
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError("atomic output write made no progress")
            offset += written
        os.fchmod(file_descriptor, 0o644)
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        _rename_atomic(temporary_name, path.name, directory_descriptor)
        temporary_name = None
        os.fsync(directory_descriptor)

        _check_path, check_descriptor = _open_output_parent(path, create=False)
        try:
            check_identity = os.fstat(check_descriptor)
            if (
                check_identity.st_dev != parent_identity.st_dev
                or check_identity.st_ino != parent_identity.st_ino
            ):
                raise ProfileError("atomic output parent changed during replacement")
        finally:
            os.close(check_descriptor)
    except BaseException:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(directory_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verifier",
        type=Path,
        default=Path(__file__).with_name("verify-current-audit.py"),
        help="path to verify-current-audit.py (default: adjacent verifier)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="atomically write JSON evidence here instead of standard output",
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        if not sys.flags.isolated or not sys.flags.safe_path:
            raise ProfileError("profiler Python isolation is required")
        profile = generate_profile(options.verifier)
        payload = render_profile(profile)
        if options.output is None:
            sys.stdout.buffer.write(payload)
        else:
            atomic_write(options.output, payload)
    except (OSError, ProfileError) as error:
        print(f"current-audit-resource-profile: {error}", file=sys.stderr)
        return 2
    return 0 if profile["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
