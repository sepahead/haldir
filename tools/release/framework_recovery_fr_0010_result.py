#!/usr/bin/env python3
"""Emit the canonical epoch-11 hosted-check result artifact.

The producer job invokes this only after its critical command has succeeded.
The resulting JSON is uploaded as an immutable GitHub Actions artifact and is
attested by a separate, no-checkout OIDC job.  This program never consumes a
secret and grants no release, deployment, publication, or tagging authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


PROTOCOL = "HALDIR_EPOCH_11_HOSTED_RESULT_V1"
REPOSITORY = "sepahead/haldir"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_GIT_OUTPUT = 2 * 1024 * 1024
WORKFLOW_CONTRACT = {
    "ci": {
        "path": ".github/workflows/ci.yml",
        "job": "supply-chain",
        "command": (
            "/usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile "
            "--norc tools/release/current-audit-gate.sh"
        ),
        "materials": (
            ".github/workflows/ci.yml",
            "tools/release/current-audit-gate.sh",
            "tools/release/framework_recovery_fr_0010.py",
            "tools/release/framework_recovery_fr_0010_result.py",
            "tools/release/verify-framework-recovery-fr-0010.py",
        ),
    },
    "formal": {
        "path": ".github/workflows/formal.yml",
        "job": "tlc-model-check",
        "command": (
            "java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC "
            "-workers auto -config formal/HaldirAuthority.cfg "
            "formal/HaldirAuthority.tla"
        ),
        "materials": (
            ".github/workflows/formal.yml",
            "formal/HaldirAuthority.cfg",
            "formal/HaldirAuthority.tla",
            "tools/pins.toml",
            "tools/release/framework_recovery_fr_0010_result.py",
        ),
    },
}


class ResultArtifactError(RuntimeError):
    """One fail-closed result-emission error."""


def _fail(code: str) -> None:
    raise ResultArtifactError(code)


def canonical_json_bytes(value: Any) -> bytes:
    """Return the sole result-artifact JSON representation."""

    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _clean_git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git(repo: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        (
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            *arguments,
        ),
        cwd=repo,
        env=_clean_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if (
        completed.returncode != 0
        or len(completed.stdout) > MAX_GIT_OUTPUT
        or len(completed.stderr) > 64 * 1024
    ):
        _fail("FR0010_RESULT_GIT")
    return completed.stdout


def _exact_environment(environment: dict[str, str], name: str) -> str:
    value = environment.get(name)
    if (
        not isinstance(value, str)
        or not value
        or "\0" in value
        or "\r" in value
        or "\n" in value
        or len(value.encode("utf-8")) > 4_096
    ):
        _fail("FR0010_RESULT_ENV:" + name)
    return value


def _positive_integer(environment: dict[str, str], name: str) -> int:
    value = _exact_environment(environment, name)
    if re.fullmatch(r"[1-9][0-9]{0,18}", value) is None:
        _fail("FR0010_RESULT_ENV:" + name)
    return int(value)


def _file_record(repo: Path, commit: str, path: str) -> dict[str, Any]:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path)
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        _fail("FR0010_RESULT_MATERIAL:" + path)
    try:
        header, observed_path = raw[:-1].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        decoded_path = observed_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        _fail("FR0010_RESULT_MATERIAL:" + path)
    if (
        decoded_path != path
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or HEX40.fullmatch(object_id) is None
    ):
        _fail("FR0010_RESULT_MATERIAL:" + path)
    payload = _git(repo, "cat-file", "blob", object_id)
    if not payload:
        _fail("FR0010_RESULT_MATERIAL:" + path)
    return {
        "path": path,
        "git_mode": mode,
        "git_object_type": "blob",
        "git_object_id": object_id,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def build_result(
    repo: Path,
    *,
    workflow: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    """Build one result from authenticated Git state and Actions identity."""

    contract = WORKFLOW_CONTRACT.get(workflow)
    if contract is None:
        _fail("FR0010_RESULT_WORKFLOW")
    if _exact_environment(environment, "GITHUB_ACTIONS") != "true":
        _fail("FR0010_RESULT_NOT_ACTIONS")
    if _exact_environment(environment, "GITHUB_REPOSITORY") != REPOSITORY:
        _fail("FR0010_RESULT_REPOSITORY")
    if _exact_environment(environment, "GITHUB_WORKFLOW") != workflow:
        _fail("FR0010_RESULT_WORKFLOW")
    if _exact_environment(environment, "GITHUB_JOB") != contract["job"]:
        _fail("FR0010_RESULT_JOB")
    commit = _exact_environment(environment, "GITHUB_SHA")
    if HEX40.fullmatch(commit) is None:
        _fail("FR0010_RESULT_COMMIT")
    head = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    tree = _git(repo, "rev-parse", "--verify", "HEAD^{tree}").decode("ascii").strip()
    if head != commit or HEX40.fullmatch(tree) is None:
        _fail("FR0010_RESULT_CHECKOUT")
    workflow_ref = _exact_environment(environment, "GITHUB_WORKFLOW_REF")
    source_ref = _exact_environment(environment, "GITHUB_REF")
    if workflow_ref != f"{REPOSITORY}/{contract['path']}@{source_ref}":
        _fail("FR0010_RESULT_WORKFLOW_REF")
    event = _exact_environment(environment, "GITHUB_EVENT_NAME")
    if event not in {"push", "pull_request", "workflow_dispatch"}:
        _fail("FR0010_RESULT_EVENT")
    repository_id = _positive_integer(environment, "GITHUB_REPOSITORY_ID")
    repository_owner_id = _positive_integer(
        environment, "GITHUB_REPOSITORY_OWNER_ID"
    )
    run_attempt = _positive_integer(environment, "GITHUB_RUN_ATTEMPT")
    if run_attempt > 8:
        _fail("FR0010_RESULT_RUN_ATTEMPT")
    return {
        "schema_version": "1.0.0",
        "protocol": PROTOCOL,
        "repository": {
            "name": REPOSITORY,
            "database_id": repository_id,
            "owner_database_id": repository_owner_id,
        },
        "subject": {
            "commit": commit,
            "tree": tree,
            "ref": source_ref,
            "event": event,
        },
        "execution": {
            "workflow": workflow,
            "workflow_ref": workflow_ref,
            "job": contract["job"],
            "run_id": _positive_integer(environment, "GITHUB_RUN_ID"),
            "run_attempt": run_attempt,
            "run_number": _positive_integer(environment, "GITHUB_RUN_NUMBER"),
            "command": contract["command"],
            "result": "PASS",
        },
        "materials": [
            _file_record(repo, commit, path) for path in contract["materials"]
        ],
        "authority": {
            "provenance_only": True,
            "release_authority": False,
            "deployment_authority": False,
            "publication_authority": False,
            "tag_authority": False,
        },
    }


def _write_exclusive(path: Path, payload: bytes, *, expected_name: str) -> None:
    if path != Path(expected_name) or path.name != expected_name:
        _fail("FR0010_RESULT_OUTPUT")
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
    parser.add_argument("--workflow", choices=sorted(WORKFLOW_CONTRACT), required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repo = Path(
            _git(Path.cwd(), "rev-parse", "--show-toplevel")
            .decode("utf-8")
            .strip()
        ).resolve(strict=True)
        result = build_result(repo, workflow=arguments.workflow, environment=dict(os.environ))
        _write_exclusive(
            arguments.output,
            canonical_json_bytes(result),
            expected_name=(
                f"epoch-11-{arguments.workflow}-result-attempt-"
                f"{result['execution']['run_attempt']}.json"
            ),
        )
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired, ResultArtifactError) as error:
        print(f"framework-recovery-fr-0010-result: {error}", file=sys.stderr)
        return 1
    print(
        "framework-recovery-fr-0010-result: OK "
        f"({arguments.workflow}; {arguments.output})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
