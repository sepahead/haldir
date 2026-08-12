#!/usr/bin/env python3
"""Emit one bounded canonical hosted result for the current Haldir source head."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, NamedTuple, NoReturn, Sequence


PROTOCOL = "HALDIR_CURRENT_HOSTED_RESULT_V1"
LINEAGE_PROTOCOL = "HALDIR_SIGNED_LINEAGE_RECOVERY_V1"
REPOSITORY = "sepahead/haldir"
REPOSITORY_DATABASE_ID = 1_292_802_592
REPOSITORY_OWNER_DATABASE_ID = 10_104_569
BREACH_COMMIT = "97e0c5dc4baa41e471f8c357b3fe7f0264cf7be8"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_GIT_OUTPUT = 8 * 1024 * 1024
MAX_GIT_ERROR_OUTPUT = 64 * 1024
MAX_ENVIRONMENT_BYTES = 4_096
MAX_MATERIAL_BYTES = 8 * 1024 * 1024
PROCESS_TIMEOUT_SECONDS = 30.0
PROCESS_REAP_TIMEOUT_SECONDS = 1.0
PROCESS_READ_BYTES = 64 * 1024
RECOVERY_RECORD = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0019-recovery.json"
)
ACTIVATION_RECORD = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0019-activation.json"
)
COMMON_MATERIALS = (
    ".github/workflows/ci.yml",
    ".github/workflows/formal.yml",
    "CONTRIBUTING.md",
    "release/0.9.0/allowed-signers",
    "release/0.9.0/current-head/README.md",
    RECOVERY_RECORD,
    "tools/release/current-audit-gate.sh",
    "tools/release/current_audit_result.py",
    "tools/release/test_verify_current_lineage.py",
    "tools/release/verify-current-lineage.py",
    "tools/verify-ci-pins.py",
)
WORKFLOWS = {
    "ci": {
        "job": "supply-chain",
        "path": ".github/workflows/ci.yml",
        "materials": (
            "Cargo.lock",
            "Cargo.toml",
            "deny.toml",
            "justfile",
            "rust-toolchain.toml",
            "tools/pinned_cargo_deny.py",
            "tools/pins.toml",
            "tools/test_pinned_cargo_deny.py",
            "tools/verify-pins.py",
        ),
    },
    "formal": {
        "job": "tlc-model-check",
        "path": ".github/workflows/formal.yml",
        "materials": (
            "formal/HaldirAuthority.cfg",
            "formal/HaldirAuthority.tla",
            "tools/pins.toml",
            "tools/run_formal.py",
            "tools/test_run_formal.py",
        ),
    },
}


class ResultError(RuntimeError):
    """One stable fail-closed result error."""


class _BoundedProcessError(RuntimeError):
    """A subprocess violated its time, output, or lifecycle boundary."""


class _ProcessResult(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes


def _fail(code: str) -> NoReturn:
    raise ResultError(code)


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
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


def _run_bounded(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    stdout_limit: int,
    stderr_limit: int,
) -> _ProcessResult:
    """Run one command with hard wall-time, byte, and process-group bounds."""

    if (
        not command
        or any(type(argument) is not str or not argument for argument in command)
        or stdout_limit < 0
        or stderr_limit < 0
    ):
        raise _BoundedProcessError("invalid process contract")
    try:
        process = subprocess.Popen(
            tuple(command),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except (OSError, ValueError) as error:
        raise _BoundedProcessError("process launch failed") from error
    if process.stdout is None or process.stderr is None:
        _stop_process_group(process)
        raise _BoundedProcessError("process pipe missing")

    streams = {
        process.stdout: (bytearray(), stdout_limit),
        process.stderr: (bytearray(), stderr_limit),
    }
    try:
        selector = selectors.DefaultSelector()
    except OSError as error:
        _stop_process_group(process)
        raise _BoundedProcessError("process selector failed") from error
    deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
    failure: str | None = None
    returncode: int | None = None
    try:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "process timed out"
                break
            events = selector.select(remaining)
            if not events:
                continue
            for key, _mask in events:
                stream = key.fileobj
                buffer, maximum = streams[stream]
                allowance = maximum + 1 - len(buffer)
                try:
                    chunk = os.read(stream.fileno(), min(PROCESS_READ_BYTES, allowance))
                except InterruptedError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > maximum:
                    failure = "process output exceeded its bound"
                    break
            if failure is not None:
                break
        if failure is None:
            try:
                returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failure = "process timed out"
    except (OSError, ValueError) as error:
        failure = "process capture failed"
        capture_error: BaseException | None = error
    except BaseException:
        _stop_process_group(process)
        raise
    else:
        capture_error = None
    finally:
        selector.close()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass

    stdout = bytes(streams[process.stdout][0])
    stderr = bytes(streams[process.stderr][0])
    _stop_process_group(process)
    if failure is not None or returncode is None:
        raise _BoundedProcessError(
            failure or "process status missing"
        ) from capture_error
    return _ProcessResult(returncode, stdout, stderr)


def _git(repo: Path, *arguments: str, check_stderr: bool = True) -> bytes:
    try:
        completed = _run_bounded(
            ("/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments),
            cwd=repo,
            environment=_git_environment(),
            stdout_limit=MAX_GIT_OUTPUT,
            stderr_limit=MAX_GIT_ERROR_OUTPUT,
        )
    except _BoundedProcessError:
        _fail("CURRENT_RESULT_GIT:" + arguments[0])
    if completed.returncode != 0 or (check_stderr and completed.stderr):
        _fail("CURRENT_RESULT_GIT:" + arguments[0])
    return completed.stdout


def _environment(environment: dict[str, str], name: str) -> str:
    value = environment.get(name)
    if (
        not isinstance(value, str)
        or not value
        or any(character in value for character in ("\0", "\r", "\n"))
        or len(value.encode("utf-8")) > MAX_ENVIRONMENT_BYTES
    ):
        _fail("CURRENT_RESULT_ENV:" + name)
    return value


def _positive_integer(environment: dict[str, str], name: str) -> int:
    value = _environment(environment, name)
    if re.fullmatch(r"[1-9][0-9]{0,18}", value) is None:
        _fail("CURRENT_RESULT_ENV:" + name)
    return int(value)


def _repository_identity(environment: dict[str, str]) -> dict[str, int | str]:
    """Return the exact immutable hosted repository identity or fail closed."""

    repository_id = _positive_integer(environment, "GITHUB_REPOSITORY_ID")
    owner_id = _positive_integer(environment, "GITHUB_REPOSITORY_OWNER_ID")
    if (
        repository_id != REPOSITORY_DATABASE_ID
        or owner_id != REPOSITORY_OWNER_DATABASE_ID
    ):
        _fail("CURRENT_RESULT_REPOSITORY_IDENTITY")
    return {
        "database_id": repository_id,
        "name": REPOSITORY,
        "owner_database_id": owner_id,
    }


def _file_record(repo: Path, commit: str, path: str) -> dict[str, Any]:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path)
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        _fail("CURRENT_RESULT_MATERIAL:" + path)
    try:
        header, observed_path = raw[:-1].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        decoded_path = observed_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        _fail("CURRENT_RESULT_MATERIAL:" + path)
    if (
        decoded_path != path
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or HEX40.fullmatch(object_id) is None
    ):
        _fail("CURRENT_RESULT_MATERIAL:" + path)
    raw_size = _git(repo, "cat-file", "-s", object_id)
    try:
        size_text = raw_size.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError:
        _fail("CURRENT_RESULT_MATERIAL:" + path)
    if re.fullmatch(r"[1-9][0-9]{0,7}", size_text) is None:
        _fail("CURRENT_RESULT_MATERIAL:" + path)
    size = int(size_text)
    if size > MAX_MATERIAL_BYTES:
        _fail("CURRENT_RESULT_MATERIAL:" + path)
    payload = _git(repo, "cat-file", "blob", object_id)
    if len(payload) != size:
        _fail("CURRENT_RESULT_MATERIAL:" + path)
    return {
        "bytes": len(payload),
        "git_mode": mode,
        "git_object_id": object_id,
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _path_exists(repo: Path, commit: str, path: str) -> bool:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path)
    if not raw:
        return False
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        _fail("CURRENT_RESULT_STAGE")
    return True


def _lineage_state(repo: Path, commit: str) -> str:
    """Derive stage from first-parent position, then cross-check its record."""

    try:
        chain = (
            _git(
                repo,
                "rev-list",
                "--first-parent",
                "--reverse",
                f"{BREACH_COMMIT}..{commit}",
            )
            .decode("ascii")
            .splitlines()
        )
    except UnicodeDecodeError:
        _fail("CURRENT_RESULT_STAGE")
    if not chain or any(HEX40.fullmatch(item) is None for item in chain):
        _fail("CURRENT_RESULT_STAGE")
    active = len(chain) >= 2
    if _path_exists(repo, commit, ACTIVATION_RECORD) != active:
        _fail("CURRENT_RESULT_STAGE")
    return (
        "ACTIVE_NO_RELEASE_AUTHORITY"
        if active
        else "RECOVERED_PENDING_HOSTED_QUALIFICATION"
    )


def build_result(
    repo: Path,
    *,
    workflow: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    contract = WORKFLOWS.get(workflow)
    if contract is None:
        _fail("CURRENT_RESULT_WORKFLOW")
    if _environment(environment, "GITHUB_ACTIONS") != "true":
        _fail("CURRENT_RESULT_NOT_ACTIONS")
    if _environment(environment, "GITHUB_REPOSITORY") != REPOSITORY:
        _fail("CURRENT_RESULT_REPOSITORY")
    if _environment(environment, "GITHUB_WORKFLOW") != workflow:
        _fail("CURRENT_RESULT_WORKFLOW")
    if _environment(environment, "GITHUB_JOB") != contract["job"]:
        _fail("CURRENT_RESULT_JOB")
    commit = _environment(environment, "GITHUB_SHA")
    if HEX40.fullmatch(commit) is None:
        _fail("CURRENT_RESULT_COMMIT")
    head = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tree = _git(repo, "rev-parse", "--verify", "HEAD^{tree}").decode().strip()
    if head != commit or HEX40.fullmatch(tree) is None:
        _fail("CURRENT_RESULT_CHECKOUT")
    source_ref = _environment(environment, "GITHUB_REF")
    if source_ref != "refs/heads/main":
        _fail("CURRENT_RESULT_REF")
    workflow_ref = _environment(environment, "GITHUB_WORKFLOW_REF")
    if workflow_ref != f"{REPOSITORY}/{contract['path']}@{source_ref}":
        _fail("CURRENT_RESULT_WORKFLOW_REF")
    event = _environment(environment, "GITHUB_EVENT_NAME")
    if event not in {"push", "workflow_dispatch"}:
        _fail("CURRENT_RESULT_EVENT")
    attempt = _positive_integer(environment, "GITHUB_RUN_ATTEMPT")
    if attempt > 8:
        _fail("CURRENT_RESULT_ATTEMPT")
    lineage_state = _lineage_state(repo, commit)
    active = lineage_state == "ACTIVE_NO_RELEASE_AUTHORITY"
    optional_materials = (ACTIVATION_RECORD,) if active else ()
    materials = sorted({*COMMON_MATERIALS, *contract["materials"], *optional_materials})
    return {
        "authority": {
            "deployment": False,
            "publication": False,
            "release": False,
            "tag": False,
        },
        "execution": {
            "job": contract["job"],
            "result": "PASS",
            "run_attempt": attempt,
            "run_id": _positive_integer(environment, "GITHUB_RUN_ID"),
            "run_number": _positive_integer(environment, "GITHUB_RUN_NUMBER"),
            "workflow": workflow,
            "workflow_ref": workflow_ref,
        },
        "lineage": {
            "protocol": LINEAGE_PROTOCOL,
            "state": lineage_state,
        },
        "materials": [_file_record(repo, commit, path) for path in materials],
        "protocol": PROTOCOL,
        "repository": _repository_identity(environment),
        "schema_version": "1.0.0",
        "subject": {
            "commit": commit,
            "event": event,
            "ref": source_ref,
            "tree": tree,
        },
    }


def write_result(path: Path, payload: bytes, *, expected_name: str) -> None:
    if path != Path(expected_name) or path.name != expected_name:
        _fail("CURRENT_RESULT_OUTPUT")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", choices=sorted(WORKFLOWS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        expected_name = (
            f"current-{arguments.workflow}-result-attempt-"
            f"{_environment(dict(os.environ), 'GITHUB_RUN_ATTEMPT')}.json"
        )
        repo = Path(
            _git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip()
        ).resolve(strict=True)
        result = build_result(
            repo,
            workflow=arguments.workflow,
            environment=dict(os.environ),
        )
        write_result(
            arguments.output,
            canonical_json_bytes(result),
            expected_name=expected_name,
        )
    except (
        ResultError,
        OSError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"current-audit-result: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"current-audit-result: OK ({arguments.output})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
