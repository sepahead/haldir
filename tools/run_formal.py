#!/usr/bin/env -S python3 -I -B
"""Run Haldir's bounded TLA+ model with verified tools and bounded resources.

The runner deliberately has no package dependencies.  It accepts only the
repository's closed TLA+ release identity, validates every cached or downloaded
byte, checks the Java specification version, invokes TLC without a shell, and
publishes a bounded raw log plus a canonical runtime record.

Online mode may populate the verified cache.  ``--offline`` performs no network
operation and fails closed unless a valid cache entry already exists.
"""

from __future__ import annotations

import sys

if not sys.flags.isolated:
    print(
        "formal-runner: FORMAL_PYTHON_NOT_ISOLATED "
        "(invoke with: python3 -I -B tools/run_formal.py)",
        file=sys.stderr,
    )
    raise SystemExit(2)

import argparse
import fcntl
import hashlib
import hmac
import http.client
import json
import math
import os
import re
import secrets
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import BinaryIO, NamedTuple, NoReturn


ADMITTED_TLA_VERSION = "1.7.4"
ADMITTED_TLA_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
ADMITTED_TLA_BYTES = 2_274_532
ADMITTED_JAVA_SPECIFICATION_VERSION = "21"
TLA_ASSET_HARD_CAP = 8 * 1024 * 1024
PINS_FILE_CAP = 64 * 1024
JAVA_OUTPUT_CAP = 64 * 1024
TLC_OUTPUT_CAP = 16 * 1024 * 1024
JAVA_TIMEOUT_SECONDS = 10.0
TLC_TIMEOUT_SECONDS = 20.0 * 60.0
DOWNLOAD_TIMEOUT_SECONDS = 300.0
DOWNLOAD_SOCKET_TIMEOUT_SECONDS = 5.0
DOWNLOAD_ATTEMPTS = 3
MAX_REDIRECTS = 5
MAX_JAVA_EXECUTABLE_BYTES = 512 * 1024 * 1024
SUCCESS_MARKER = b"Model checking completed. No error has been found."
RUNTIME_SCHEMA = "HALDIR_FORMAL_RUNTIME_V1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
JAVA_PROPERTY = re.compile(rb"^[ \t]*([A-Za-z0-9_.-]+)[ \t]*=[ \t]*(.*?)[ \t]*$")
ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "release-assets.githubusercontent.com",
    }
)


class FormalRunnerError(RuntimeError):
    """A stable fail-closed formal-runner error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FormalPins(NamedTuple):
    """The admitted formal-tool identity."""

    version: str
    sha256: str
    size: int
    java_specification_version: str


class ProcessResult(NamedTuple):
    """One bounded child-process result."""

    returncode: int
    output: bytes
    output_bytes: int
    termination: str


class JavaIdentity(NamedTuple):
    """Validated Java identity captured before TLC."""

    executable: Path
    executable_bytes: int
    executable_sha256: str
    device: int
    inode: int
    modified_ns: int
    specification_version: str
    vendor: str | None
    runtime_version: str | None
    vm_name: str | None
    properties_output_sha256: str


class FileRecord(NamedTuple):
    """One exact material file bound into the runtime record."""

    path: str
    size: int
    sha256: str


def _fail(code: str) -> NoReturn:
    raise FormalRunnerError(code)


def _type_int(value: object) -> bool:
    return type(value) is int


def _repository_root() -> Path:
    try:
        script = Path(__file__).resolve(strict=True)
        root = script.parent.parent.resolve(strict=True)
    except OSError:
        _fail("FORMAL_REPOSITORY")
    if not (root / "Cargo.toml").is_file() or not (root / "formal").is_dir():
        _fail("FORMAL_REPOSITORY")
    return root


def _read_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    reject_writable: bool = True,
) -> bytes:
    if not _type_int(maximum_bytes) or maximum_bytes < 0:
        _fail("FORMAL_FILE_BOUND")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail("FORMAL_FILE_OPEN:" + path.name)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 0
            or metadata.st_size > maximum_bytes
            or (reject_writable and metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
        ):
            _fail("FORMAL_FILE_TYPE:" + path.name)
        output = bytearray()
        while len(output) <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
        if len(output) > maximum_bytes or os.read(descriptor, 1):
            _fail("FORMAL_FILE_BOUND:" + path.name)
        if len(output) != metadata.st_size:
            _fail("FORMAL_FILE_CHANGED:" + path.name)
        return bytes(output)
    except OSError:
        _fail("FORMAL_FILE_READ:" + path.name)
    finally:
        os.close(descriptor)


def _file_record(path: Path, *, label: str, maximum_bytes: int) -> FileRecord:
    payload = _read_regular_file(path, maximum_bytes=maximum_bytes)
    return FileRecord(
        path=label, size=len(payload), sha256=hashlib.sha256(payload).hexdigest()
    )


def _material_payload(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
) -> tuple[bytes, FileRecord]:
    payload = _read_regular_file(path, maximum_bytes=maximum_bytes)
    return (
        payload,
        FileRecord(
            path=label,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        ),
    )


def _material_record(record: FileRecord) -> dict[str, object]:
    return {
        "bytes": record.size,
        "path": record.path,
        "sha256": record.sha256,
    }


def _require_unchanged_material(
    path: Path,
    *,
    expected: FileRecord,
    maximum_bytes: int,
) -> None:
    observed = _file_record(
        path,
        label=expected.path,
        maximum_bytes=maximum_bytes,
    )
    if observed != expected:
        _fail("FORMAL_MATERIAL_CHANGED:" + expected.path)


def load_pins(repository: Path) -> FormalPins:
    """Load and close the current schema-v1 formal pin table."""

    payload = _read_regular_file(
        repository / "tools" / "pins.toml",
        maximum_bytes=PINS_FILE_CAP,
    )
    if b"\0" in payload:
        _fail("FORMAL_PINS_NUL")
    try:
        decoded = payload.decode("utf-8")
        document = tomllib.loads(decoded)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        _fail("FORMAL_PINS_PARSE")
    if (
        not isinstance(document, dict)
        or type(document.get("schema_version")) is not int
    ):
        _fail("FORMAL_PINS_SCHEMA")
    if document["schema_version"] != 1:
        _fail("FORMAL_PINS_SCHEMA")
    formal = document.get("formal")
    if not isinstance(formal, dict) or set(formal) != {
        "tla_tools_version",
        "tla_tools_sha256",
    }:
        _fail("FORMAL_PINS_FIELDS")
    version = formal["tla_tools_version"]
    digest = formal["tla_tools_sha256"]
    if (
        type(version) is not str
        or SEMVER.fullmatch(version) is None
        or type(digest) is not str
        or HEX64.fullmatch(digest) is None
    ):
        _fail("FORMAL_PINS_TYPES")
    if (
        version != ADMITTED_TLA_VERSION
        or not hmac.compare_digest(digest, ADMITTED_TLA_SHA256)
        or ADMITTED_TLA_BYTES > TLA_ASSET_HARD_CAP
    ):
        _fail("FORMAL_PINS_UNADMITTED")
    return FormalPins(
        version=version,
        sha256=digest,
        size=ADMITTED_TLA_BYTES,
        java_specification_version=ADMITTED_JAVA_SPECIFICATION_VERSION,
    )


def _ensure_private_directory(path: Path) -> Path:
    """Create or validate one non-symlink, non-shared directory."""

    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
    except OSError:
        _fail("FORMAL_DIRECTORY:" + path.name)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail("FORMAL_DIRECTORY:" + path.name)
    return path


def _resolve_log_path(
    requested: Path | None,
    *,
    formal_root: Path,
    asset: Path | None = None,
) -> tuple[Path, Path, Path]:
    """Resolve the collision-free log, runtime-record, and lock paths."""

    candidate = requested or formal_root / "tlc.log"
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        requested_metadata = candidate.lstat()
    except FileNotFoundError:
        requested_metadata = None
    except OSError:
        _fail("FORMAL_OUTPUT_PATH")
    if requested_metadata is not None and stat.S_ISLNK(requested_metadata.st_mode):
        _fail("FORMAL_OUTPUT_PATH")
    try:
        log_path = candidate.resolve(strict=False)
        root = formal_root.resolve(strict=True)
    except OSError:
        _fail("FORMAL_OUTPUT_PATH")
    runtime_path = root / "formal-runtime.json"
    lock_path = root / ".formal-runner.lock"
    if (
        log_path.parent != root
        or log_path in {runtime_path, lock_path}
        or (asset is not None and log_path == asset.resolve(strict=True))
    ):
        _fail("FORMAL_OUTPUT_PATH")
    try:
        existing = log_path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError:
        _fail("FORMAL_OUTPUT_PATH")
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail("FORMAL_OUTPUT_PATH")
    return log_path, runtime_path, lock_path


def _acquire_run_lock(path: Path) -> int:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            _fail("FORMAL_RUN_LOCK")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _fail("FORMAL_RUN_BUSY")
    except FormalRunnerError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    except OSError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _fail("FORMAL_RUN_LOCK")


def _release_run_lock(descriptor: int) -> None:
    cleanup_ok = True
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        cleanup_ok = False
    try:
        os.close(descriptor)
    except OSError:
        cleanup_ok = False
    if not cleanup_ok:
        _fail("FORMAL_RUN_LOCK_RELEASE")


def _asset_name(pins: FormalPins) -> str:
    return f"tla2tools-{pins.version}-{pins.sha256}.jar"


def _asset_url(pins: FormalPins) -> str:
    return (
        "https://github.com/tlaplus/tlaplus/releases/download/"
        f"v{pins.version}/tla2tools.jar"
    )


def _hash_regular_file(
    path: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> tuple[int, str]:
    """Validate one exact non-symlink regular file through its open descriptor."""

    if (
        not _type_int(expected_bytes)
        or expected_bytes < 0
        or type(expected_sha256) is not str
        or HEX64.fullmatch(expected_sha256) is None
    ):
        _fail("FORMAL_ASSET_EXPECTATION")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail("FORMAL_ASSET_OPEN")
    digest = hashlib.sha256()
    consumed = 0
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or metadata.st_size != expected_bytes
        ):
            _fail("FORMAL_ASSET_TYPE")
        while consumed < expected_bytes:
            chunk = os.read(descriptor, min(64 * 1024, expected_bytes - consumed))
            if not chunk:
                _fail("FORMAL_ASSET_TRUNCATED")
            digest.update(chunk)
            consumed += len(chunk)
        if os.read(descriptor, 1):
            _fail("FORMAL_ASSET_GROWTH")
        observed = digest.hexdigest()
        if not hmac.compare_digest(observed, expected_sha256):
            _fail("FORMAL_ASSET_DIGEST")
        return consumed, observed
    except OSError:
        _fail("FORMAL_ASSET_READ")
    finally:
        os.close(descriptor)


def validate_cached_asset(path: Path, pins: FormalPins) -> Path:
    """Validate and return one exact cached TLA+ jar."""

    _hash_regular_file(
        path,
        expected_bytes=pins.size,
        expected_sha256=pins.sha256,
    )
    return path


def _snapshot_asset(source: Path, destination: Path, pins: FormalPins) -> Path:
    payload = _read_regular_file(source, maximum_bytes=TLA_ASSET_HARD_CAP)
    if len(payload) != pins.size or not hmac.compare_digest(
        hashlib.sha256(payload).hexdigest(), pins.sha256
    ):
        _fail("FORMAL_ASSET_SNAPSHOT")
    _write_private_file(destination, payload)
    return validate_cached_asset(destination, pins)


def _validate_download_url(url: str, *, initial: bool, pins: FormalPins) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        _fail("FORMAL_DOWNLOAD_URL")
    if (
        type(url) is not str
        or parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in {None, 443}
    ):
        _fail("FORMAL_DOWNLOAD_URL")
    if initial and (
        parsed.hostname != "github.com"
        or parsed.query
        or parsed.path
        != f"/tlaplus/tlaplus/releases/download/v{pins.version}/tla2tools.jar"
    ):
        _fail("FORMAL_DOWNLOAD_URL")


class _StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, pins: FormalPins) -> None:
        super().__init__()
        self._pins = pins
        self._redirects = 0

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: Mapping[str, str],
        new_url: str,
    ) -> urllib.request.Request | None:
        self._redirects += 1
        if self._redirects > MAX_REDIRECTS:
            _fail("FORMAL_DOWNLOAD_REDIRECTS")
        _validate_download_url(new_url, initial=False, pins=self._pins)
        return super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            new_url,
        )


def _ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _single_header(headers: object, name: str) -> str | None:
    getter = getattr(headers, "get_all", None)
    if getter is None:
        _fail("FORMAL_DOWNLOAD_HEADERS")
    try:
        values = getter(name)
    except (AttributeError, KeyError, TypeError, ValueError):
        _fail("FORMAL_DOWNLOAD_HEADERS")
    if values is None:
        return None
    if not isinstance(values, list) or len(values) != 1 or type(values[0]) is not str:
        _fail("FORMAL_DOWNLOAD_HEADERS")
    return values[0]


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written < 1:
            _fail("FORMAL_WRITE")
        view = view[written:]


def _open_private_temp(parent: Path, prefix: str) -> tuple[int, Path]:
    for _attempt in range(32):
        candidate = parent / f".{prefix}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            return descriptor, candidate
        except FileExistsError:
            continue
        except OSError:
            _fail("FORMAL_TEMP_OPEN")
    _fail("FORMAL_TEMP_COLLISION")


def _write_private_file(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError:
        _fail("FORMAL_SNAPSHOT_OPEN")
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    except OSError:
        _fail("FORMAL_SNAPSHOT_WRITE")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            _fail("FORMAL_SNAPSHOT_CLOSE")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail("FORMAL_DIRECTORY_FSYNC")
    try:
        os.fsync(descriptor)
    except OSError:
        _fail("FORMAL_DIRECTORY_FSYNC")
    finally:
        os.close(descriptor)


def _download_to_descriptor(
    descriptor: int,
    *,
    pins: FormalPins,
    deadline: float,
) -> None:
    url = _asset_url(pins)
    _validate_download_url(url, initial=True, pins=pins)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _fail("FORMAL_DOWNLOAD_TIMEOUT")
    handler = _StrictRedirectHandler(pins)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ssl_context()),
        handler,
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "haldir-formal-runner/1",
        },
        method="GET",
    )
    socket_timeout = min(DOWNLOAD_SOCKET_TIMEOUT_SECONDS, remaining)
    try:
        response = opener.open(request, timeout=socket_timeout)
    except FormalRunnerError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        _fail("FORMAL_DOWNLOAD_OPEN")
    digest = hashlib.sha256()
    consumed = 0
    try:
        status = getattr(response, "status", None)
        if status != 200:
            _fail("FORMAL_DOWNLOAD_STATUS")
        try:
            final_url = response.geturl()
        except (AttributeError, ValueError):
            _fail("FORMAL_DOWNLOAD_URL")
        _validate_download_url(final_url, initial=False, pins=pins)
        content_length = _single_header(response.headers, "Content-Length")
        if content_length is not None and (
            len(content_length) > 20
            or not content_length.isascii()
            or not content_length.isdigit()
            or (len(content_length) > 1 and content_length.startswith("0"))
            or int(content_length) != pins.size
        ):
            _fail("FORMAL_DOWNLOAD_LENGTH")
        content_encoding = _single_header(response.headers, "Content-Encoding")
        if content_encoding not in {None, "identity"}:
            _fail("FORMAL_DOWNLOAD_ENCODING")
        while consumed < pins.size:
            if time.monotonic() >= deadline:
                _fail("FORMAL_DOWNLOAD_TIMEOUT")
            try:
                chunk = response.read(min(64 * 1024, pins.size - consumed))
            except (OSError, EOFError, http.client.HTTPException):
                _fail("FORMAL_DOWNLOAD_READ")
            if not chunk:
                _fail("FORMAL_DOWNLOAD_TRUNCATED")
            if type(chunk) is not bytes:
                _fail("FORMAL_DOWNLOAD_READ")
            digest.update(chunk)
            _write_all(descriptor, chunk)
            consumed += len(chunk)
        try:
            extra = response.read(1)
        except (OSError, EOFError, http.client.HTTPException):
            _fail("FORMAL_DOWNLOAD_READ")
        if extra:
            _fail("FORMAL_DOWNLOAD_GROWTH")
        if not hmac.compare_digest(digest.hexdigest(), pins.sha256):
            _fail("FORMAL_DOWNLOAD_DIGEST")
        os.fsync(descriptor)
    finally:
        try:
            response.close()
        except (OSError, http.client.HTTPException):
            _fail("FORMAL_DOWNLOAD_CLOSE")


def ensure_asset(
    cache_directory: Path,
    *,
    pins: FormalPins,
    offline: bool,
) -> Path:
    """Return a verified cache entry, acquiring it only when permitted."""

    cache = _ensure_private_directory(cache_directory)
    destination = cache / _asset_name(pins)
    try:
        return validate_cached_asset(destination, pins)
    except FormalRunnerError:
        if offline:
            _fail("FORMAL_OFFLINE_CACHE")
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT_SECONDS
    last_error: FormalRunnerError | None = None
    for attempt in range(DOWNLOAD_ATTEMPTS):
        descriptor, temporary = _open_private_temp(cache, "tla2tools")
        try:
            try:
                _download_to_descriptor(descriptor, pins=pins, deadline=deadline)
            finally:
                os.close(descriptor)
            validate_cached_asset(temporary, pins)
            try:
                validate_cached_asset(destination, pins)
            except FormalRunnerError:
                os.replace(temporary, destination)
                _fsync_directory(cache)
            else:
                temporary.unlink()
            return validate_cached_asset(destination, pins)
        except FormalRunnerError as error:
            last_error = error
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                _fail("FORMAL_TEMP_CLEANUP")
            if error.code in {
                "FORMAL_DIRECTORY_FSYNC",
                "FORMAL_CACHE_PUBLISH",
            }:
                raise
            if attempt + 1 < DOWNLOAD_ATTEMPTS and time.monotonic() < deadline:
                continue
            break
        except OSError:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                _fail("FORMAL_TEMP_CLEANUP")
            _fail("FORMAL_CACHE_PUBLISH")
    if last_error is not None:
        raise last_error
    _fail("FORMAL_DOWNLOAD")


def _leader_exited_unreaped(process: subprocess.Popen[bytes]) -> bool:
    try:
        status = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOWAIT | os.WNOHANG,
        )
    except OSError:
        _fail("FORMAL_PROCESS_IDENTITY")
    return status is not None


def _kill_group(process: subprocess.Popen[bytes], *, zombie_leader: bool) -> bool:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except PermissionError:
        if zombie_leader:
            return True
        try:
            return _leader_exited_unreaped(process)
        except FormalRunnerError:
            return False
    except OSError:
        return False
    return True


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> bool:
    try:
        zombie = _leader_exited_unreaped(process)
    except FormalRunnerError:
        return False
    cleanup_ok = _kill_group(process, zombie_leader=zombie)
    if not cleanup_ok:
        try:
            process.kill()
        except ProcessLookupError:
            cleanup_ok = True
        except OSError:
            cleanup_ok = False
        else:
            cleanup_ok = True
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        cleanup_ok = False
    return cleanup_ok


def _run_bounded(
    command: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit: int,
    sink: Callable[[bytes], None] | None = None,
    capture: bool,
) -> ProcessResult:
    """Run one process group while bounding time, output, and descendants."""

    if (
        not command
        or any(type(item) is not str or not item for item in command)
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or not _type_int(output_limit)
        or output_limit < 0
        or type(capture) is not bool
    ):
        _fail("FORMAL_PROCESS_ARGUMENT")
    selector: selectors.BaseSelector | None = None
    process: subprocess.Popen[bytes] | None = None
    pipe: BinaryIO | None = None
    captured = bytearray()
    consumed = 0
    returncode: int | None = None
    termination = "EXITED"
    leader_exited = False
    group_signaled = False
    cleanup_ok = True
    pending_error: BaseException | None = None
    try:
        selector = selectors.DefaultSelector()
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            start_new_session=True,
        )
        pipe = process.stdout
        if pipe is None:
            _fail("FORMAL_PROCESS_PIPE")
        selector.register(pipe, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        cleanup_deadline: float | None = None
        while selector.get_map():
            active_deadline = (
                cleanup_deadline if cleanup_deadline is not None else deadline
            )
            remaining = active_deadline - time.monotonic()
            if remaining <= 0:
                termination = "DESCENDANT_PIPE_TIMEOUT" if leader_exited else "TIMEOUT"
                break
            ready = selector.select(min(remaining, 0.02))
            for key, _mask in ready:
                allowance = output_limit - consumed
                read_size = max(1, min(64 * 1024, allowance + 1))
                chunk = os.read(key.fileobj.fileno(), read_size)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                accepted = chunk[: max(0, allowance)]
                if accepted:
                    if capture:
                        captured.extend(accepted)
                    if sink is not None:
                        try:
                            sink(accepted)
                        except FormalRunnerError:
                            raise
                        except OSError:
                            _fail("FORMAL_PROCESS_SINK")
                    consumed += len(accepted)
                if len(chunk) > len(accepted):
                    termination = "OUTPUT_LIMIT"
                    break
            if termination != "EXITED":
                break
            if not leader_exited and _leader_exited_unreaped(process):
                leader_exited = True
                cleanup_ok = _kill_group(process, zombie_leader=True) and cleanup_ok
                group_signaled = True
                cleanup_deadline = min(deadline, time.monotonic() + 1.0)
        if termination == "EXITED":
            while not leader_exited:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    termination = "TIMEOUT"
                    break
                if _leader_exited_unreaped(process):
                    leader_exited = True
                    break
                time.sleep(min(0.01, remaining))
        if leader_exited and not group_signaled:
            cleanup_ok = _kill_group(process, zombie_leader=True) and cleanup_ok
            group_signaled = True
        if not leader_exited or termination != "EXITED":
            cleanup_ok = _terminate_and_reap(process) and cleanup_ok
        else:
            try:
                returncode = process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_ok = False
        if returncode is None and process.returncode is not None:
            returncode = process.returncode
    except BaseException as error:
        pending_error = error
    finally:
        if process is not None and returncode is None and process.returncode is None:
            try:
                cleanup_ok = _terminate_and_reap(process) and cleanup_ok
                returncode = process.returncode
            except BaseException:
                cleanup_ok = False
        if selector is not None:
            try:
                selector.close()
            except BaseException:
                cleanup_ok = False
        if pipe is not None:
            try:
                pipe.close()
            except BaseException:
                cleanup_ok = False
    if not cleanup_ok:
        _fail("FORMAL_PROCESS_CLEANUP")
    if pending_error is not None:
        if isinstance(pending_error, FormalRunnerError):
            raise pending_error
        if isinstance(pending_error, (OSError, subprocess.SubprocessError)):
            _fail("FORMAL_PROCESS_LAUNCH")
        raise pending_error
    if returncode is None:
        _fail("FORMAL_PROCESS_REAP")
    return ProcessResult(
        returncode=returncode,
        output=bytes(captured),
        output_bytes=consumed,
        termination=termination,
    )


def _child_environment(private_root: Path, java: Path) -> dict[str, str]:
    home = _ensure_private_directory(private_root / "home")
    temporary = _ensure_private_directory(private_root / "tmp")
    return {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{java.parent}:/usr/bin:/bin",
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }


def _resolve_java(value: str | None) -> Path:
    candidate = value if value is not None else shutil.which("java")
    if not candidate:
        _fail("FORMAL_JAVA_MISSING")
    try:
        path = Path(candidate)
        if not path.is_absolute():
            path = Path.cwd() / path
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        _fail("FORMAL_JAVA_MISSING")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(resolved, os.X_OK)
    ):
        _fail("FORMAL_JAVA_TYPE")
    return resolved


def _java_stat(path: Path) -> os.stat_result:
    try:
        metadata = path.stat()
    except OSError:
        _fail("FORMAL_JAVA_CHANGED")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(path, os.X_OK)
        or metadata.st_size < 1
        or metadata.st_size > MAX_JAVA_EXECUTABLE_BYTES
    ):
        _fail("FORMAL_JAVA_CHANGED")
    return metadata


def _require_java_unchanged(identity: JavaIdentity) -> None:
    metadata = _java_stat(identity.executable)
    if (
        metadata.st_dev != identity.device
        or metadata.st_ino != identity.inode
        or metadata.st_size != identity.executable_bytes
        or metadata.st_mtime_ns != identity.modified_ns
        or not hmac.compare_digest(
            _sha256_unchecked_file(identity.executable, metadata.st_size),
            identity.executable_sha256,
        )
    ):
        _fail("FORMAL_JAVA_CHANGED")


def _java_properties(output: bytes) -> dict[str, list[str]]:
    properties: dict[str, list[str]] = {}
    for line in output.splitlines():
        match = JAVA_PROPERTY.fullmatch(line)
        if match is None:
            continue
        try:
            key = match.group(1).decode("ascii")
            value = match.group(2).decode("utf-8")
        except UnicodeDecodeError:
            _fail("FORMAL_JAVA_OUTPUT")
        properties.setdefault(key, []).append(value)
    return properties


def _optional_single_property(
    properties: Mapping[str, list[str]],
    name: str,
) -> str | None:
    values = properties.get(name)
    if values is None:
        return None
    if len(values) != 1 or not values[0]:
        _fail("FORMAL_JAVA_PROPERTY:" + name)
    return values[0]


def validate_java(
    value: str | None,
    *,
    pins: FormalPins,
    private_root: Path,
) -> tuple[JavaIdentity, dict[str, str]]:
    """Resolve and execute Java, accepting only the pinned specification version."""

    java = _resolve_java(value)
    metadata = _java_stat(java)
    executable_bytes = metadata.st_size
    executable_sha256 = _sha256_unchecked_file(java, metadata.st_size)
    environment = _child_environment(private_root, java)
    result = _run_bounded(
        (str(java), "-XshowSettings:properties", "-version"),
        cwd=private_root,
        environment=environment,
        timeout_seconds=JAVA_TIMEOUT_SECONDS,
        output_limit=JAVA_OUTPUT_CAP,
        capture=True,
    )
    if result.termination != "EXITED" or result.returncode != 0:
        _fail("FORMAL_JAVA_EXECUTION")
    properties = _java_properties(result.output)
    specifications = properties.get("java.specification.version")
    if specifications != [pins.java_specification_version]:
        _fail("FORMAL_JAVA_VERSION")
    identity = JavaIdentity(
        executable=java,
        executable_bytes=executable_bytes,
        executable_sha256=executable_sha256,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        modified_ns=metadata.st_mtime_ns,
        specification_version=specifications[0],
        vendor=_optional_single_property(properties, "java.vendor"),
        runtime_version=_optional_single_property(properties, "java.runtime.version"),
        vm_name=_optional_single_property(properties, "java.vm.name"),
        properties_output_sha256=hashlib.sha256(result.output).hexdigest(),
    )
    _require_java_unchanged(identity)
    return identity, environment


def _sha256_unchecked_file(path: Path, expected_bytes: int) -> str:
    """Measure a previously type-checked executable before exact revalidation."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail("FORMAL_FILE_OPEN:" + path.name)
    digest = hashlib.sha256()
    consumed = 0
    try:
        try:
            while consumed < expected_bytes:
                chunk = os.read(descriptor, min(64 * 1024, expected_bytes - consumed))
                if not chunk:
                    _fail("FORMAL_FILE_CHANGED:" + path.name)
                consumed += len(chunk)
                digest.update(chunk)
            if os.read(descriptor, 1):
                _fail("FORMAL_FILE_CHANGED:" + path.name)
        except OSError:
            _fail("FORMAL_FILE_READ:" + path.name)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            _fail("FORMAL_FILE_CLOSE:" + path.name)
    return digest.hexdigest()


def _publish_temp(temporary: Path, destination: Path) -> None:
    replaced = False
    try:
        os.replace(temporary, destination)
        replaced = True
        _fsync_directory(destination.parent)
    except OSError:
        if not replaced:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                _fail("FORMAL_TEMP_CLEANUP")
        _fail("FORMAL_PUBLISH:" + destination.name)
    except FormalRunnerError:
        if not replaced:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                _fail("FORMAL_TEMP_CLEANUP")
        raise


def _atomic_json(path: Path, value: object) -> None:
    try:
        payload = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError):
        _fail("FORMAL_RUNTIME_JSON")
    parent = _ensure_private_directory(path.parent)
    descriptor, temporary = _open_private_temp(parent, path.name)
    failure: FormalRunnerError | None = None
    try:
        try:
            _write_all(descriptor, payload)
        except (FormalRunnerError, OSError):
            failure = FormalRunnerError("FORMAL_RUNTIME_WRITE")
        if failure is None:
            try:
                os.fsync(descriptor)
            except OSError:
                failure = FormalRunnerError("FORMAL_RUNTIME_FSYNC")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            failure = FormalRunnerError("FORMAL_RUNTIME_CLOSE")
    if failure is not None:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            _fail("FORMAL_TEMP_CLEANUP")
        raise failure
    _publish_temp(temporary, path)


def _invalidate_runtime_record(path: Path) -> None:
    """Remove an older record before replacing its paired log."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        _fail("FORMAL_RUNTIME_INVALIDATE")
    if stat.S_ISDIR(metadata.st_mode):
        _fail("FORMAL_RUNTIME_INVALIDATE")
    try:
        path.unlink()
        _fsync_directory(path.parent)
    except OSError:
        _fail("FORMAL_RUNTIME_INVALIDATE")


def _count_success_markers(path: Path) -> int:
    payload = _read_regular_file(
        path,
        maximum_bytes=TLC_OUTPUT_CAP,
        reject_writable=True,
    )
    return sum(1 for line in payload.splitlines() if line == SUCCESS_MARKER)


def _relative_or_placeholder(path: Path, repository: Path, placeholder: str) -> str:
    try:
        return path.relative_to(repository).as_posix()
    except ValueError:
        return placeholder


def run_tlc(
    *,
    repository: Path,
    pins: FormalPins,
    asset: Path,
    java_identity: JavaIdentity,
    environment: Mapping[str, str],
    log_path: Path,
    runtime_path: Path,
    scratch_root: Path,
) -> dict[str, object]:
    """Run TLC on private verified snapshots and publish a bound result pair."""

    try:
        if (
            log_path.resolve(strict=False) == runtime_path.resolve(strict=False)
            or log_path.resolve(strict=False) == asset.resolve(strict=True)
            or runtime_path.resolve(strict=False) == asset.resolve(strict=True)
        ):
            _fail("FORMAL_OUTPUT_PATH")
    except OSError:
        _fail("FORMAL_OUTPUT_PATH")
    runner_path = repository / "tools" / "run_formal.py"
    pins_path = repository / "tools" / "pins.toml"
    spec_path = repository / "formal" / "HaldirAuthority.tla"
    config_path = repository / "formal" / "HaldirAuthority.cfg"
    runner_record = _file_record(
        runner_path,
        label="tools/run_formal.py",
        maximum_bytes=2 * 1024 * 1024,
    )
    pins_record = _file_record(
        pins_path,
        label="tools/pins.toml",
        maximum_bytes=PINS_FILE_CAP,
    )
    spec_payload, spec_record = _material_payload(
        spec_path,
        label="formal/HaldirAuthority.tla",
        maximum_bytes=1024 * 1024,
    )
    config_payload, config_record = _material_payload(
        config_path,
        label="formal/HaldirAuthority.cfg",
        maximum_bytes=1024 * 1024,
    )
    material_checks = (
        (runner_path, runner_record, 2 * 1024 * 1024),
        (pins_path, pins_record, PINS_FILE_CAP),
        (spec_path, spec_record, 1024 * 1024),
        (config_path, config_record, 1024 * 1024),
    )
    log_parent = _ensure_private_directory(log_path.parent)
    descriptor, temporary_log = _open_private_temp(log_parent, log_path.name)

    def sink(chunk: bytes) -> None:
        _write_all(descriptor, chunk)

    result: ProcessResult | None = None
    process_error: FormalRunnerError | None = None
    try:
        try:
            temporary_context = tempfile.TemporaryDirectory(
                prefix="tlc-",
                dir=scratch_root,
            )
        except OSError:
            _fail("FORMAL_SCRATCH_CREATE")
        try:
            with temporary_context as scratch:
                scratch_path = Path(scratch)
                input_root = _ensure_private_directory(scratch_path / "inputs")
                snapshot_spec = input_root / "HaldirAuthority.tla"
                snapshot_config = input_root / "HaldirAuthority.cfg"
                snapshot_asset = input_root / "tla2tools.jar"
                _write_private_file(snapshot_spec, spec_payload)
                _write_private_file(snapshot_config, config_payload)
                _snapshot_asset(asset, snapshot_asset, pins)
                metadir = scratch_path / "states"
                _require_java_unchanged(java_identity)
                command = (
                    str(java_identity.executable),
                    "-XX:+UseParallelGC",
                    "-cp",
                    str(snapshot_asset),
                    "tlc2.TLC",
                    "-workers",
                    "auto",
                    "-metadir",
                    str(metadir),
                    "-config",
                    str(snapshot_config),
                    str(snapshot_spec),
                )
                try:
                    result = _run_bounded(
                        command,
                        cwd=repository,
                        environment=environment,
                        timeout_seconds=TLC_TIMEOUT_SECONDS,
                        output_limit=TLC_OUTPUT_CAP,
                        sink=sink,
                        capture=False,
                    )
                except FormalRunnerError as error:
                    process_error = error
                    result = ProcessResult(
                        returncode=-1,
                        output=b"",
                        output_bytes=0,
                        termination="RUNNER_ERROR",
                    )
        except OSError:
            _fail("FORMAL_SCRATCH_CLEANUP")
    finally:
        log_error: FormalRunnerError | None = None
        try:
            try:
                os.fsync(descriptor)
            except OSError:
                log_error = FormalRunnerError("FORMAL_LOG_FSYNC")
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    log_error = FormalRunnerError("FORMAL_LOG_CLOSE")
            if log_error is None:
                try:
                    _invalidate_runtime_record(runtime_path)
                    _publish_temp(temporary_log, log_path)
                except BaseException:
                    try:
                        temporary_log.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        _fail("FORMAL_TEMP_CLEANUP")
                    raise
        finally:
            if log_error is not None:
                try:
                    temporary_log.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    _fail("FORMAL_TEMP_CLEANUP")
        if log_error is not None:
            raise log_error
    if result is None:
        _fail("FORMAL_TLC_RESULT")
    log_bytes, log_sha256 = _hash_log(log_path)
    marker_count = _count_success_markers(log_path)
    post_error: FormalRunnerError | None = None
    try:
        _require_java_unchanged(java_identity)
        for path, expected, maximum in material_checks:
            _require_unchanged_material(
                path,
                expected=expected,
                maximum_bytes=maximum,
            )
    except FormalRunnerError as error:
        post_error = error
    if result.output_bytes != log_bytes and post_error is None:
        post_error = FormalRunnerError("FORMAL_LOG_ACCOUNTING")
    passed = (
        process_error is None
        and post_error is None
        and result.termination == "EXITED"
        and result.returncode == 0
        and marker_count == 1
    )
    logical_argv = [
        "<java>",
        "-XX:+UseParallelGC",
        "-cp",
        "<verified-tla2tools.jar>",
        "tlc2.TLC",
        "-workers",
        "auto",
        "-metadir",
        "<ephemeral-metadir>",
        "-config",
        "<verified-HaldirAuthority.cfg>",
        "<verified-HaldirAuthority.tla>",
    ]
    runtime = {
        "argv": logical_argv,
        "cwd": ".",
        "error": (
            process_error.code
            if process_error is not None
            else (post_error.code if post_error is not None else None)
        ),
        "java": {
            "device": java_identity.device,
            "executable_bytes": java_identity.executable_bytes,
            "executable_sha256": java_identity.executable_sha256,
            "inode": java_identity.inode,
            "modified_ns": java_identity.modified_ns,
            "runtime_version": java_identity.runtime_version,
            "specification_version": java_identity.specification_version,
            "vendor": java_identity.vendor,
            "vm_name": java_identity.vm_name,
            "version_output_sha256": java_identity.properties_output_sha256,
        },
        "materials": [
            _material_record(record)
            for record in sorted(
                (runner_record, pins_record, spec_record, config_record),
                key=lambda item: item.path,
            )
        ],
        "result": "PASS" if passed else "FAIL",
        "schema": RUNTIME_SCHEMA,
        "tla_tools": {
            "bytes": pins.size,
            "sha256": pins.sha256,
            "version": pins.version,
        },
        "tlc": {
            "exit_status": result.returncode,
            "log_bytes": log_bytes,
            "log_path": _relative_or_placeholder(
                log_path, repository, "<external-log>"
            ),
            "log_sha256": log_sha256,
            "output_bound_bytes": TLC_OUTPUT_CAP,
            "success_marker_count": marker_count,
            "termination": result.termination,
            "timeout_seconds": int(TLC_TIMEOUT_SECONDS),
        },
    }
    _atomic_json(runtime_path, runtime)
    if not passed:
        if process_error is not None:
            raise process_error
        if post_error is not None:
            raise post_error
        if result.termination != "EXITED":
            _fail("FORMAL_TLC_" + result.termination)
        if result.returncode != 0:
            _fail("FORMAL_TLC_EXIT")
        _fail("FORMAL_TLC_MARKER")
    return runtime


def _hash_log(path: Path) -> tuple[int, str]:
    payload = _read_regular_file(
        path,
        maximum_bytes=TLC_OUTPUT_CAP,
        reject_writable=True,
    )
    return len(payload), hashlib.sha256(payload).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="prohibit acquisition and require a verified cached TLA+ jar",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="verified cache directory (default: target/formal/cache)",
    )
    parser.add_argument(
        "--java",
        help="Java executable (default: the first java on PATH)",
    )
    parser.add_argument(
        "--log",
        type=Path,
        help=(
            "raw TLC log directly below target/formal (default: target/formal/tlc.log)"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repository = _repository_root()
        pins = load_pins(repository)
        cache = arguments.cache_dir or repository / "target" / "formal" / "cache"
        if not cache.is_absolute():
            cache = Path.cwd() / cache
        cache = cache.absolute()
        formal_root = _ensure_private_directory(repository / "target" / "formal")
        log, runtime_path, lock_path = _resolve_log_path(
            arguments.log,
            formal_root=formal_root,
        )
        lock = _acquire_run_lock(lock_path)
        try:
            asset = ensure_asset(cache, pins=pins, offline=arguments.offline)
            log, runtime_path, _lock_path = _resolve_log_path(
                log,
                formal_root=formal_root,
                asset=asset,
            )
            try:
                runtime_context = tempfile.TemporaryDirectory(
                    prefix="runtime-",
                    dir=formal_root,
                )
            except OSError:
                _fail("FORMAL_RUNTIME_CREATE")
            try:
                with runtime_context as private:
                    java, environment = validate_java(
                        arguments.java,
                        pins=pins,
                        private_root=Path(private),
                    )
                    run_tlc(
                        repository=repository,
                        pins=pins,
                        asset=asset,
                        java_identity=java,
                        environment=environment,
                        log_path=log,
                        runtime_path=runtime_path,
                        scratch_root=formal_root,
                    )
            except OSError:
                _fail("FORMAL_RUNTIME_CLEANUP")
        finally:
            _release_run_lock(lock)
        print(f"formal-runner: OK (log={log}; runtime={runtime_path})")
        return 0
    except FormalRunnerError as error:
        print(f"formal-runner: {error.code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
