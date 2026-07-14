#!/usr/bin/env python3
"""Verify the immutable Haldir 0.9 audit cut without network access."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_MANIFEST_BYTES = 256 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_HANDOFF = {
    "HALDIR_V1_0_AGENT_TASK_LEDGER.yaml": "b77f64703f7c9528453783a1f25ecc86c179c741bca0b9e3034327d83633e8bd",
    "HALDIR_V1_0_ARCHITECTURE.md": "4b167dd0be9caa10bf4eb5f26f92025853cda044624b88c7fc9f5a967d0ba677",
    "HALDIR_V1_0_ARTIFACT_SHA256SUMS.txt": "1350e08bcdf65eac8f0be86272c133167efdd5462c0d19b18432b0207b210408",
    "HALDIR_V1_0_ARTIFACT_VALIDATION_REPORT.md": "100170daa81dcbbb6b0d6e1baed21c63992193d7469360eb235bec3e0de8524d",
    "HALDIR_V1_0_CORE_CONTRACT_SCHEMA.json": "fecff9e28dc65f8f24595c771b0393627f0b9ce838538ca7ed704fa2d1f6b43e",
    "HALDIR_V1_0_GO_NO_GO_CHECKLIST.md": "410ae84b8982c4c8cef768c26c3cd69439abbdaa5253f3234fe4e8ea8545eccf",
    "HALDIR_V1_0_MIGRATION_AND_ECOSYSTEM.md": "36d6eef8ab32c999cbb016e4531b85df000f96ff9345f459deb9e76ed3c51594",
    "HALDIR_V1_0_RELEASE_BLUEPRINT.md": "eff0e6eff85d71cde0df30d333f6dcf128c1c71b550b3052cc3c8e30b28a7bc8",
    "HALDIR_V1_0_RELEASE_MANIFEST_TEMPLATE.json": "e13df9209c574c3ff09b69a0919238ca988d478a1351301bd643558ddbbe3c68",
    "PACKAGE_INDEX.md": "4b4b0855e8725f591edea2e453de15d9e086b05e6217805fcfbc0704eabf1dd6",
}

EXPECTED_TOP_LEVEL = {
    "schema_version",
    "release_target",
    "captured_at_utc",
    "author",
    "source",
    "handoff",
    "toolchains",
    "locked_inputs",
    "ncp",
    "deployment",
    "formal_model",
    "retained_evidence",
    "baseline",
    "repository_publication_state",
}


class AuditError(ValueError):
    """An audit input is malformed or does not match its immutable source."""


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        payload = handle.read(limit + 1)
    if len(payload) > limit:
        raise AuditError(f"AUDIT_RESOURCE_BOUND:{path.name}")
    return payload


def read_bounded_gzip(path: Path, limit: int = MAX_LOG_BYTES) -> bytes:
    """Return bounded decompressed bytes or reject oversized/trailing streams."""

    try:
        with gzip.open(path, "rb") as handle:
            payload = handle.read(limit + 1)
    except (OSError, EOFError) as error:
        raise AuditError("AUDIT_LOG_INVALID_GZIP") from error
    if len(payload) > limit:
        raise AuditError("AUDIT_LOG_RESOURCE_BOUND")
    return payload


def _load_json(path: Path, limit: int) -> dict[str, Any]:
    try:
        value = json.loads(_read_bounded(path, limit))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"AUDIT_JSON_INVALID:{path.name}") from error
    if not isinstance(value, dict):
        raise AuditError(f"AUDIT_JSON_NOT_OBJECT:{path.name}")
    return value


def _require_hex(value: Any, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AuditError(f"AUDIT_INVALID_HEX:{field}")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git(repo: Path, *arguments: str, limit: int = 4 * 1024 * 1024) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise AuditError(f"AUDIT_GIT_LOOKUP_FAILED:{' '.join(arguments)}") from error
    if len(result.stdout) > limit:
        raise AuditError("AUDIT_GIT_OUTPUT_BOUND")
    return result.stdout


def _git_file(repo: Path, commit: str, path: str) -> bytes:
    return _git(repo, "show", f"{commit}:{path}")


def _verify_handoff(manifest: dict[str, Any]) -> None:
    handoff = manifest.get("handoff")
    if not isinstance(handoff, dict) or handoff.get("verified_against_supplied_checksum_manifest") is not True:
        raise AuditError("AUDIT_HANDOFF_NOT_VERIFIED")
    files = handoff.get("files")
    if not isinstance(files, list):
        raise AuditError("AUDIT_HANDOFF_FILES_INVALID")
    observed: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise AuditError("AUDIT_HANDOFF_ENTRY_INVALID")
        path = item.get("path")
        digest = _require_hex(item.get("sha256"), HEX64, "handoff.sha256")
        if not isinstance(path, str) or path in observed:
            raise AuditError("AUDIT_HANDOFF_PATH_INVALID_OR_DUPLICATE")
        observed[path] = digest
    if observed != EXPECTED_HANDOFF:
        raise AuditError("AUDIT_HANDOFF_DIGEST_MISMATCH")


def _verify_source_bound_files(manifest: dict[str, Any], repo: Path, commit: str) -> None:
    source = manifest["source"]
    tree = _require_hex(source.get("tree"), HEX40, "source.tree")
    actual_tree = _git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    if actual_tree != tree:
        raise AuditError("AUDIT_SOURCE_TREE_MISMATCH")

    locked = manifest["locked_inputs"]
    expected_files = {
        "Cargo.lock": locked.get("cargo_lock_sha256"),
        "rust-toolchain.toml": locked.get("rust_toolchain_sha256"),
        "deny.toml": locked.get("dependency_policy_sha256"),
        "deploy/secure-reference-v1/profile.json": manifest["deployment"].get("profile_sha256"),
        "deploy/secure-reference-v1/README.md": manifest["deployment"].get("readme_sha256"),
        "formal/HaldirAuthority.tla": manifest["formal_model"].get("specification_sha256"),
        "formal/HaldirAuthority.cfg": manifest["formal_model"].get("configuration_sha256"),
    }
    for item in manifest["retained_evidence"]:
        expected_files[item["path"]] = item["sha256"]
    for path, expected in expected_files.items():
        digest = _require_hex(expected, HEX64, path)
        if _sha256(_git_file(repo, commit, path)) != digest:
            raise AuditError(f"AUDIT_SOURCE_FILE_MISMATCH:{path}")

    cargo_toml = _git_file(repo, commit, "Cargo.toml").decode("utf-8")
    ncp = manifest["ncp"]
    if ncp.get("protocol_1_0_qualified") is not False:
        raise AuditError("AUDIT_NCP_1_0_MUST_BE_UNQUALIFIED_AT_CUT")
    commit_pin = _require_hex(ncp.get("commit"), HEX40, "ncp.commit")
    if f'rev = "{commit_pin}"' not in cargo_toml or 'version = "=0.8.0"' not in cargo_toml:
        raise AuditError("AUDIT_NCP_PIN_MISMATCH")


def _verify_baseline(manifest: dict[str, Any], repo: Path) -> None:
    baseline = manifest["baseline"]
    if baseline.get("command") != "bash tools/p0r-exit-gate.sh" or baseline.get("exit_status") != 0:
        raise AuditError("AUDIT_BASELINE_RESULT_INVALID")
    if baseline.get("passed_gates") != 19 or baseline.get("failed_gates") != 0:
        raise AuditError("AUDIT_BASELINE_SUMMARY_INVALID")
    log_path = repo / baseline["log"]
    payload = read_bounded_gzip(log_path)
    if len(payload) != baseline.get("uncompressed_bytes"):
        raise AuditError("AUDIT_LOG_SIZE_MISMATCH")
    if len(payload.splitlines()) != baseline.get("uncompressed_lines"):
        raise AuditError("AUDIT_LOG_LINE_COUNT_MISMATCH")
    expected = _require_hex(baseline.get("uncompressed_sha256"), HEX64, "baseline.sha256")
    if _sha256(payload) != expected:
        raise AuditError("AUDIT_LOG_DIGEST_MISMATCH")
    if b"P0-R exit gate: 19 passed, 0 failed" not in payload or not payload.rstrip().endswith(
        b"BASELINE_EXIT_STATUS=0"
    ):
        raise AuditError("AUDIT_LOG_SUCCESS_MARKER_MISSING")

    result = _load_json(repo / "release/0.9.0/evidence/baseline-p0r.json", MAX_MANIFEST_BYTES)
    if result.get("source_commit") != manifest["source"]["commit"]:
        raise AuditError("AUDIT_BASELINE_SOURCE_MISMATCH")
    if result.get("exit_status") != 0 or result.get("result") != "pass":
        raise AuditError("AUDIT_BASELINE_RECORD_MISMATCH")
    if result.get("log", {}).get("uncompressed_sha256") != expected:
        raise AuditError("AUDIT_BASELINE_DIGEST_RECORD_MISMATCH")


def verify(manifest_path: Path, repo: Path) -> None:
    """Verify one audit manifest against immutable objects in ``repo``."""

    manifest = _load_json(manifest_path, MAX_MANIFEST_BYTES)
    if set(manifest) != EXPECTED_TOP_LEVEL:
        raise AuditError("AUDIT_TOP_LEVEL_FIELDS_INVALID")
    if manifest.get("schema_version") != "1.0.0" or manifest.get("release_target") != "0.9.0":
        raise AuditError("AUDIT_VERSION_INVALID")
    if manifest.get("author", {}).get("name") != "Sepehr Mahmoudian":
        raise AuditError("AUDIT_AUTHOR_INVALID")

    source = manifest.get("source")
    if not isinstance(source, dict) or source.get("tree_clean") is not True:
        raise AuditError("AUDIT_SOURCE_NOT_CLEAN")
    commit = _require_hex(source.get("commit"), HEX40, "source.commit")
    if source.get("origin_main_commit") != commit or source.get("branch") != "main":
        raise AuditError("AUDIT_SOURCE_BRANCH_MISMATCH")
    if source.get("submodules") != []:
        raise AuditError("AUDIT_UNEXPECTED_SUBMODULES")

    _verify_handoff(manifest)
    _verify_source_bound_files(manifest, repo, commit)
    _verify_baseline(manifest, repo)

    publication = manifest.get("repository_publication_state")
    if publication != {"remote_tags": [], "github_releases": []}:
        raise AuditError("AUDIT_INITIAL_PUBLICATION_STATE_INVALID")


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    manifest = repo / "release/0.9.0/audit-inputs.json"
    try:
        verify(manifest, repo)
    except AuditError as error:
        print(f"verify-audit-inputs: FAIL: {error}", file=sys.stderr)
        return 1
    print("verify-audit-inputs: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

