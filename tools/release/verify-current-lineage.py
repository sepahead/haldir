#!/usr/bin/env python3
"""Verify Haldir's compact epoch-19 signed-main recovery and successors."""

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
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple, NoReturn, Sequence


PROTOCOL = "HALDIR_SIGNED_LINEAGE_RECOVERY_V1"
RECOVERY_ID = "FR-0019"
REPOSITORY = "sepahead/haldir"
LAST_VALID_COMMIT = "079a8fd227bdf6476d307f792cfcb070d6fc3a8c"
BREACH_COMMIT = "97e0c5dc4baa41e471f8c357b3fe7f0264cf7be8"
BREACH_TREE = "431a9ce47d3cdc615cb5265a2d73c80f2f9ba9ca"
BREACH_SUBJECT = "fix: harden cryptographic key provisioning"
RECOVERY_SUBJECT = "release: recover signed main lineage (epoch 19)"
ACTIVATION_SUBJECT = "release: activate signed main lineage (epoch 19)"
AUTHOR_NAME = "Sepehr Mahmoudian"
AUTHOR_EMAIL = "sepmhn@gmail.com"
SIGNER_PRINCIPAL = "sepmhn@gmail.com"
SIGNER_FINGERPRINT = "SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU"
ALLOWED_SIGNERS_PATH = "release/0.9.0/allowed-signers"
ALLOWED_SIGNERS_SHA256 = (
    "88eddddf1b3a6d0176acf2ec88b1d3c120453e2658651c49b82d41057caa78ed"
)
RECOVERY_RECORD_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0019-recovery.json"
)
ACTIVATION_RECORD_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0019-activation.json"
)
VERIFIER_PATH = "tools/release/verify-current-lineage.py"
VERIFIER_TEST_PATH = "tools/release/test_verify_current_lineage.py"
GATE_PATH = "tools/release/current-audit-gate.sh"
CURRENT_RESULT_PATH = "tools/release/current_audit_result.py"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
UTC_TIMESTAMP = re.compile(
    r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
MAX_GIT_OUTPUT = 8 * 1024 * 1024
MAX_GIT_ERROR_OUTPUT = 64 * 1024
MAX_RECORD_BYTES = 64 * 1024
MAX_SUCCESSOR_PATHS = 256
PROCESS_TIMEOUT_SECONDS = 30.0
PROCESS_REAP_TIMEOUT_SECONDS = 1.0
PROCESS_READ_BYTES = 64 * 1024
REQUIRED_HOSTED_CHECKS = (
    "build-test",
    "clean-build",
    "feature-matrix",
    "interop",
    "macos-compile",
    "supply-chain",
    "tlc-model-check",
)
GITHUB_ACTIONS_APP_ID = 15_368
REPOSITORY_DATABASE_ID = 1_292_802_592
REPOSITORY_OWNER_DATABASE_ID = 10_104_569

FROZEN_HISTORICAL_TOOLS = frozenset(
    {
        "tools/release/framework_recovery_fr_0017.py",
        "tools/release/framework_recovery_fr_0017_capture.py",
        "tools/release/framework_recovery_fr_0017_result.py",
        "tools/release/test_verify_framework_recovery_fr_0017.py",
        "tools/release/verify-framework-recovery-fr-0017.py",
        ALLOWED_SIGNERS_PATH,
    }
)
PROTECTED_AFTER_ACTIVATION = frozenset(
    {
        ".github/workflows/ci.yml",
        ".github/workflows/formal.yml",
        "CONTRIBUTING.md",
        ALLOWED_SIGNERS_PATH,
        GATE_PATH,
        VERIFIER_PATH,
        VERIFIER_TEST_PATH,
        CURRENT_RESULT_PATH,
        "justfile",
        "release/0.9.0/current-head/README.md",
        "tools/pinned_cargo_deny.py",
        "tools/pins.toml",
        "tools/run_formal.py",
        "tools/test_run_formal.py",
        "tools/verify-pins.py",
        "tools/verify-ci-pins.py",
        "tools/test_pinned_cargo_deny.py",
        RECOVERY_RECORD_PATH,
        ACTIVATION_RECORD_PATH,
    }
)
FROZEN_HISTORICAL_PREFIXES = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0010",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0011",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0012",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0013",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0014",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0015",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0016",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0017",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0018",
    "release/0.9.0/current-head/evidence/framework-recovery-fr-",
    "release/0.9.0/current-head/reviews/framework-recovery-fr-",
)
PROTECTED_AFTER_ACTIVATION_PREFIXES = (
    # Protect the namespace, not merely today's two workflow files. Otherwise an
    # ordinary successor could add a new workflow with unrelated permissions and
    # silently step outside the reviewed hosted-execution boundary.
    ".github/workflows/",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0019",
)


class LineageError(RuntimeError):
    """One stable fail-closed lineage failure."""


class _BoundedProcessError(RuntimeError):
    """A subprocess violated its time, output, or lifecycle boundary."""


class _ProcessResult(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes


def _fail(code: str) -> NoReturn:
    raise LineageError(code)


def canonical_json_bytes(value: Any) -> bytes:
    """Return the sole accepted record representation."""

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


def expected_recovery_record() -> dict[str, Any]:
    """Return the signed recovery commit's exact declarative record."""

    return {
        "authority": {
            "deployment": False,
            "publication": False,
            "release": False,
            "tag": False,
        },
        "breach": {
            "classification": "GITHUB_SQUASH_COMMIT_OUTSIDE_EPOCH_18_IDENTITY",
            "commit": BREACH_COMMIT,
            "parent": LAST_VALID_COMMIT,
            "subject": BREACH_SUBJECT,
            "tree": BREACH_TREE,
        },
        "delivery_contract": {
            "merge_buttons_authorized": False,
            "required_author_email": AUTHOR_EMAIL,
            "required_committer_email": AUTHOR_EMAIL,
            "required_signer_fingerprint": SIGNER_FINGERPRINT,
        },
        "limitations": [
            "RECOVERY_COMMIT_BOOTSTRAPS_THIS_REVIEWED_VERIFIER",
            "HOSTED_SETTINGS_REMAIN_MUTABLE_EXTERNAL_STATE",
            "HOSTED_COMMIT_METADATA_RULE_UNAVAILABLE_ON_USER_REPOSITORY",
            "WEB_REBASE_BUTTON_REMAINS_A_HOSTED_DELIVERY_RISK",
            "NO_INDEPENDENT_REVIEWER_AT_RECOVERY",
            "NO_RELEASE_OR_DEPLOYMENT_AUTHORITY",
        ],
        "prior_valid_commit": LAST_VALID_COMMIT,
        "protocol": PROTOCOL,
        "recovery_id": RECOVERY_ID,
        "schema_version": "1.0.0",
        "stage": "RECOVERY",
        "state_after": "RECOVERED_PENDING_HOSTED_QUALIFICATION",
    }


def _git_environment() -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return environment


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill the isolated child group and reap its leader within a fixed bound."""

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


def _git(repo: Path, *arguments: str, max_bytes: int = MAX_GIT_OUTPUT) -> bytes:
    try:
        completed = _run_bounded(
            ("/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments),
            cwd=repo,
            environment=_git_environment(),
            stdout_limit=max_bytes,
            stderr_limit=MAX_GIT_ERROR_OUTPUT,
        )
    except _BoundedProcessError:
        _fail("LINEAGE_GIT:" + arguments[0])
    if completed.returncode != 0 or completed.stderr:
        _fail("LINEAGE_GIT:" + arguments[0])
    return completed.stdout


def _metadata(repo: Path, commit: str) -> dict[str, str]:
    fields = (
        "commit",
        "tree",
        "parents",
        "author_name",
        "author_email",
        "committer_name",
        "committer_email",
        "author_date",
        "committer_date",
        "subject",
    )
    format_string = "%H%x00%T%x00%P%x00%an%x00%ae%x00%cn%x00%ce%x00%aI%x00%cI%x00%s"
    raw = _git(repo, "show", "-s", f"--format={format_string}", commit)
    try:
        values = raw.rstrip(b"\n").decode("utf-8").split("\0")
    except UnicodeDecodeError:
        _fail("LINEAGE_COMMIT_METADATA")
    if len(values) != len(fields):
        _fail("LINEAGE_COMMIT_METADATA")
    result = dict(zip(fields, values, strict=True))
    if (
        HEX40.fullmatch(result["commit"]) is None
        or HEX40.fullmatch(result["tree"]) is None
        or len(result["parents"].split()) > 1
    ):
        _fail("LINEAGE_COMMIT_METADATA")
    return result


def _verify_breach(repo: Path) -> None:
    metadata = _metadata(repo, BREACH_COMMIT)
    if metadata != {
        "commit": BREACH_COMMIT,
        "tree": BREACH_TREE,
        "parents": LAST_VALID_COMMIT,
        "author_name": AUTHOR_NAME,
        "author_email": "Sepehr.Mahmoudian@gmail.com",
        "committer_name": "GitHub",
        "committer_email": "noreply@github.com",
        "author_date": "2026-08-10T02:07:46+02:00",
        "committer_date": "2026-08-10T02:07:46+02:00",
        "subject": BREACH_SUBJECT,
    }:
        _fail("LINEAGE_BREACH_IDENTITY")


def _allowed_signers(repo: Path) -> bytes:
    payload = _git(
        repo,
        "show",
        f"{LAST_VALID_COMMIT}:{ALLOWED_SIGNERS_PATH}",
        max_bytes=4_096,
    )
    if hashlib.sha256(payload).hexdigest() != ALLOWED_SIGNERS_SHA256:
        _fail("LINEAGE_SIGNER_ROOT")
    return payload


def _verify_signed_commit(
    repo: Path,
    commit: str,
    *,
    parent: str,
    subject: str | None,
    allowed_signers: bytes,
) -> dict[str, str]:
    metadata = _metadata(repo, commit)
    if (
        metadata["parents"] != parent
        or (subject is not None and metadata["subject"] != subject)
        or metadata["author_name"] != AUTHOR_NAME
        or metadata["author_email"] != AUTHOR_EMAIL
        or metadata["committer_name"] != AUTHOR_NAME
        or metadata["committer_email"] != AUTHOR_EMAIL
        or metadata["author_date"] != metadata["committer_date"]
    ):
        _fail("LINEAGE_COMMIT_IDENTITY")

    descriptor, name = tempfile.mkstemp(prefix="haldir-lineage-signers-")
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as destination:
            descriptor = -1
            destination.write(allowed_signers)
            destination.flush()
            os.fsync(destination.fileno())
        try:
            completed = _run_bounded(
                (
                    "/usr/bin/git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    f"gpg.ssh.allowedSignersFile={name}",
                    "-c",
                    f"gpg.ssh.revocationFile={os.devnull}",
                    "-c",
                    "gpg.ssh.program=/usr/bin/ssh-keygen",
                    "-c",
                    "gpg.format=ssh",
                    "verify-commit",
                    commit,
                ),
                cwd=repo,
                environment=_git_environment(),
                stdout_limit=MAX_GIT_ERROR_OUTPUT,
                stderr_limit=MAX_GIT_ERROR_OUTPUT,
            )
        except _BoundedProcessError:
            _fail("LINEAGE_COMMIT_SIGNATURE")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(name)
        except OSError:
            pass
    expected = (
        f'Good "git" signature for {SIGNER_PRINCIPAL} with ED25519 key '
        f"{SIGNER_FINGERPRINT}\n"
    ).encode("ascii")
    if completed.returncode != 0 or completed.stdout or completed.stderr != expected:
        _fail("LINEAGE_COMMIT_SIGNATURE")
    return metadata


def _changed_paths(repo: Path, parent: str, commit: str) -> dict[str, str]:
    raw = _git(
        repo,
        "diff-tree",
        "--no-commit-id",
        "--no-renames",
        "-r",
        "--name-status",
        "-z",
        parent,
        commit,
    )
    parts = raw.split(b"\0")
    if parts[-1:] == [b""]:
        parts.pop()
    if len(parts) % 2 != 0 or len(parts) // 2 > MAX_SUCCESSOR_PATHS:
        _fail("LINEAGE_CHANGED_PATHS")
    result: dict[str, str] = {}
    for index in range(0, len(parts), 2):
        try:
            status = parts[index].decode("ascii")
            path = parts[index + 1].decode("utf-8")
        except UnicodeDecodeError:
            _fail("LINEAGE_CHANGED_PATHS")
        if status not in {"A", "M", "D"} or not path or path in result:
            _fail("LINEAGE_CHANGED_PATHS")
        result[path] = status
    return result


def _historical_path_is_frozen(path: str) -> bool:
    return path in FROZEN_HISTORICAL_TOOLS or any(
        path.startswith(prefix) for prefix in FROZEN_HISTORICAL_PREFIXES
    )


def _successor_path_is_protected(path: str) -> bool:
    return path in PROTECTED_AFTER_ACTIVATION or any(
        path.startswith(prefix) for prefix in PROTECTED_AFTER_ACTIVATION_PREFIXES
    )


def _validate_recovery_paths(paths: dict[str, str]) -> None:
    """Require recovery bootstrap inputs and forbid stage collapse/history edits."""

    if (
        not paths
        or paths.get(RECOVERY_RECORD_PATH) != "A"
        or paths.get(VERIFIER_PATH) != "A"
        or paths.get(VERIFIER_TEST_PATH) != "A"
        or ACTIVATION_RECORD_PATH in paths
        or any(_historical_path_is_frozen(path) for path in paths)
    ):
        _fail("LINEAGE_RECOVERY_SCOPE")


def _read_canonical_json(repo: Path, commit: str, path: str) -> dict[str, Any]:
    payload = _git(repo, "show", f"{commit}:{path}", max_bytes=MAX_RECORD_BYTES)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("LINEAGE_RECORD_JSON:" + path)
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        _fail("LINEAGE_RECORD_CANONICAL:" + path)
    return value


def _parse_utc(value: object, label: str) -> str:
    if not isinstance(value, str) or UTC_TIMESTAMP.fullmatch(value) is None:
        _fail("LINEAGE_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("LINEAGE_TIMESTAMP:" + label)
    if parsed.tzinfo != timezone.utc:
        _fail("LINEAGE_TIMESTAMP:" + label)
    return value


def _validate_hosted_run(value: object, *, workflow: str, recovery_commit: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "conclusion",
        "event",
        "head_sha",
        "run_attempt",
        "run_id",
        "url",
        "workflow",
    }:
        _fail("LINEAGE_HOSTED_RUN:" + workflow)
    run_id = value["run_id"]
    if (
        type(run_id) is not int
        or run_id <= 0
        or type(value["run_attempt"]) is not int
        or not 1 <= value["run_attempt"] <= 8
        or value["workflow"] != workflow
        or value["event"] != "push"
        or value["head_sha"] != recovery_commit
        or value["conclusion"] != "success"
        or value["url"] != f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    ):
        _fail("LINEAGE_HOSTED_RUN:" + workflow)


def _validate_activation_record(
    value: dict[str, Any],
    *,
    recovery_commit: str,
    recovery_tree: str,
) -> None:
    if set(value) != {
        "authority",
        "hosted_qualification",
        "limitations",
        "observed_at_utc",
        "protocol",
        "recovery_commit",
        "recovery_id",
        "recovery_tree",
        "repository_settings",
        "schema_version",
        "stage",
        "state_after",
    }:
        _fail("LINEAGE_ACTIVATION_FIELDS")
    if (
        value["schema_version"] != "1.0.0"
        or value["protocol"] != PROTOCOL
        or value["recovery_id"] != RECOVERY_ID
        or value["stage"] != "ACTIVATION"
        or value["state_after"] != "ACTIVE_NO_RELEASE_AUTHORITY"
        or value["recovery_commit"] != recovery_commit
        or value["recovery_tree"] != recovery_tree
        or value["authority"]
        != {
            "deployment": False,
            "publication": False,
            "release": False,
            "tag": False,
        }
        or value["limitations"]
        != [
            "HOSTED_RESULTS_ARE_OWNER_OBSERVED_NOT_CRYPTOGRAPHICALLY_IMPORTED",
            "HOSTED_SETTINGS_REMAIN_MUTABLE_EXTERNAL_STATE",
            "HOSTED_COMMIT_METADATA_RULE_UNAVAILABLE_ON_USER_REPOSITORY",
            "WEB_REBASE_BUTTON_REMAINS_A_HOSTED_DELIVERY_RISK",
            "NO_INDEPENDENT_REVIEWER_AT_ACTIVATION",
            "NO_RELEASE_OR_DEPLOYMENT_AUTHORITY",
        ]
    ):
        _fail("LINEAGE_ACTIVATION_VALUE")
    _parse_utc(value["observed_at_utc"], "activation")
    hosted = value["hosted_qualification"]
    if not isinstance(hosted, dict) or set(hosted) != {"ci", "formal"}:
        _fail("LINEAGE_HOSTED_QUALIFICATION")
    _validate_hosted_run(hosted["ci"], workflow="ci", recovery_commit=recovery_commit)
    _validate_hosted_run(
        hosted["formal"], workflow="formal", recovery_commit=recovery_commit
    )
    settings = value["repository_settings"]
    if not isinstance(settings, dict) or set(settings) != {
        "allow_deletions",
        "allow_force_pushes",
        "allow_merge_commit",
        "allow_rebase_merge",
        "allow_squash_merge",
        "captured_at_utc",
        "commit_metadata_identity_rule_available",
        "enforce_admins",
        "observation_is_mutable_external_state",
        "repository_database_id",
        "repository_owner_database_id",
        "repository_owner_type",
        "required_conversation_resolution",
        "required_linear_history",
        "required_pull_request_reviews",
        "required_signatures",
        "required_status_checks",
        "strict_required_status_checks",
        "writer_allowlist_ruleset_bypass_actor_id",
        "writer_allowlist_ruleset_bypass_actor_type",
        "writer_allowlist_ruleset_bypass_mode",
        "writer_allowlist_ruleset_current_user_can_bypass",
        "writer_allowlist_ruleset_excluded_refs",
        "writer_allowlist_ruleset_enforcement",
        "writer_allowlist_ruleset_id",
        "writer_allowlist_ruleset_included_refs",
        "writer_allowlist_ruleset_name",
        "writer_allowlist_ruleset_owner_bypass",
        "writer_allowlist_ruleset_rules",
        "writer_allowlist_ruleset_source",
        "writer_allowlist_ruleset_source_type",
        "writer_allowlist_ruleset_target",
    }:
        _fail("LINEAGE_SETTINGS_FIELDS")
    _parse_utc(settings["captured_at_utc"], "settings")
    expected_checks = [
        {"app_id": GITHUB_ACTIONS_APP_ID, "context": context}
        for context in REQUIRED_HOSTED_CHECKS
    ]
    if (
        settings["allow_deletions"] is not False
        or settings["allow_force_pushes"] is not False
        or settings["allow_merge_commit"] is not False
        or settings["allow_squash_merge"] is not False
        or settings["allow_rebase_merge"] is not True
        or settings["commit_metadata_identity_rule_available"] is not False
        or settings["enforce_admins"] is not True
        or settings["observation_is_mutable_external_state"] is not True
        or settings["repository_database_id"] != REPOSITORY_DATABASE_ID
        or settings["repository_owner_database_id"] != REPOSITORY_OWNER_DATABASE_ID
        or settings["repository_owner_type"] != "User"
        or settings["required_conversation_resolution"] is not False
        or settings["required_linear_history"] is not True
        or settings["required_pull_request_reviews"] is not False
        or settings["required_signatures"] is not True
        or settings["required_status_checks"] != expected_checks
        or settings["strict_required_status_checks"] is not True
        or settings["writer_allowlist_ruleset_bypass_actor_id"]
        != REPOSITORY_OWNER_DATABASE_ID
        or settings["writer_allowlist_ruleset_bypass_actor_type"] != "User"
        or settings["writer_allowlist_ruleset_bypass_mode"] != "always"
        or settings["writer_allowlist_ruleset_current_user_can_bypass"] != "always"
        or settings["writer_allowlist_ruleset_excluded_refs"] != []
        or settings["writer_allowlist_ruleset_enforcement"] != "active"
        or type(settings["writer_allowlist_ruleset_id"]) is not int
        or settings["writer_allowlist_ruleset_id"] <= 0
        or settings["writer_allowlist_ruleset_included_refs"] != ["refs/heads/main"]
        or settings["writer_allowlist_ruleset_name"] != "haldir-main-writer-allowlist"
        or settings["writer_allowlist_ruleset_owner_bypass"] is not True
        or settings["writer_allowlist_ruleset_rules"] != ["update"]
        or settings["writer_allowlist_ruleset_source"] != REPOSITORY
        or settings["writer_allowlist_ruleset_source_type"] != "Repository"
        or settings["writer_allowlist_ruleset_target"] != "branch"
    ):
        _fail("LINEAGE_SETTINGS_VALUE")


def verify(repo: Path, commit: str) -> dict[str, Any]:
    """Verify `commit` against the exact epoch-19 recovery state machine."""

    head = _git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    if HEX40.fullmatch(head) is None:
        _fail("LINEAGE_HEAD")
    _verify_breach(repo)
    try:
        ancestor = _run_bounded(
            (
                "/usr/bin/git",
                "-c",
                "core.hooksPath=/dev/null",
                "merge-base",
                "--is-ancestor",
                BREACH_COMMIT,
                head,
            ),
            cwd=repo,
            environment=_git_environment(),
            stdout_limit=4_096,
            stderr_limit=MAX_GIT_ERROR_OUTPUT,
        )
    except _BoundedProcessError:
        _fail("LINEAGE_BREACH_ANCESTRY")
    if ancestor.returncode != 0 or ancestor.stdout or ancestor.stderr:
        _fail("LINEAGE_BREACH_ANCESTRY")
    chain = (
        _git(
            repo,
            "rev-list",
            "--first-parent",
            "--reverse",
            f"{BREACH_COMMIT}..{head}",
        )
        .decode("ascii")
        .splitlines()
    )
    if not chain:
        _fail("LINEAGE_RECOVERY_MISSING")
    allowed_signers = _allowed_signers(repo)
    recovery_commit = chain[0]
    recovery_metadata = _verify_signed_commit(
        repo,
        recovery_commit,
        parent=BREACH_COMMIT,
        subject=RECOVERY_SUBJECT,
        allowed_signers=allowed_signers,
    )
    recovery_paths = _changed_paths(repo, BREACH_COMMIT, recovery_commit)
    _validate_recovery_paths(recovery_paths)
    recovery_record = _read_canonical_json(repo, recovery_commit, RECOVERY_RECORD_PATH)
    if recovery_record != expected_recovery_record():
        _fail("LINEAGE_RECOVERY_RECORD")

    state = "RECOVERED_PENDING_HOSTED_QUALIFICATION"
    activation_commit: str | None = None
    if len(chain) >= 2:
        activation_commit = chain[1]
        _verify_signed_commit(
            repo,
            activation_commit,
            parent=recovery_commit,
            subject=ACTIVATION_SUBJECT,
            allowed_signers=allowed_signers,
        )
        if _changed_paths(repo, recovery_commit, activation_commit) != {
            ACTIVATION_RECORD_PATH: "A"
        }:
            _fail("LINEAGE_ACTIVATION_SCOPE")
        activation_record = _read_canonical_json(
            repo, activation_commit, ACTIVATION_RECORD_PATH
        )
        _validate_activation_record(
            activation_record,
            recovery_commit=recovery_commit,
            recovery_tree=recovery_metadata["tree"],
        )
        state = "ACTIVE_NO_RELEASE_AUTHORITY"

    previous = activation_commit
    if previous is not None:
        for successor in chain[2:]:
            _verify_signed_commit(
                repo,
                successor,
                parent=previous,
                subject=None,
                allowed_signers=allowed_signers,
            )
            paths = _changed_paths(repo, previous, successor)
            if not paths or any(_successor_path_is_protected(path) for path in paths):
                _fail("LINEAGE_SUCCESSOR_SCOPE")
            previous = successor
    elif len(chain) > 1:
        _fail("LINEAGE_STAGE")

    return {
        "activation_commit": activation_commit,
        "authority": {
            "deployment": False,
            "publication": False,
            "release": False,
            "tag": False,
        },
        "head": head,
        "recovery_commit": recovery_commit,
        "state": state,
    }


def _repo() -> Path:
    try:
        raw = _run_bounded(
            ("/usr/bin/git", "rev-parse", "--show-toplevel"),
            cwd=Path.cwd(),
            environment=_git_environment(),
            stdout_limit=4_096,
            stderr_limit=MAX_GIT_ERROR_OUTPUT,
        )
    except _BoundedProcessError:
        _fail("LINEAGE_REPOSITORY")
    if raw.returncode != 0 or raw.stderr:
        _fail("LINEAGE_REPOSITORY")
    try:
        return Path(raw.stdout.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _fail("LINEAGE_REPOSITORY")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", default="HEAD", help="commit to verify")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = verify(_repo(), arguments.commit)
    except (
        LineageError,
        OSError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"verify-current-lineage: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "verify-current-lineage: OK "
        f"({result['state']}; signed linear epoch 19; release NO_GO)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
