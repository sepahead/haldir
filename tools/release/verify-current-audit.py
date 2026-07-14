#!/usr/bin/env python3
"""Verify the current-head Haldir 0.9 audit cut without network access."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


MAX_JSON_BYTES = 256 * 1024
MAX_REQUIREMENTS_BYTES = 4 * 1024 * 1024
MAX_COMPRESSED_LOG_BYTES = 256 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_GIT_BYTES = 8 * 1024 * 1024
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

SOURCE_COMMIT = "2bfcabe5bf9fd6c428f7d50132bd36ec4e147438"
SOURCE_TREE = "8d8cdda01d25bc9f3c6a2911b2c4464f5c7505e5"
SOURCE_PARENT = "9cf56e149a105026b072c9073d7e87b93103966e"
CAPTURED_AT_UTC = "2026-07-14T15:10:06Z"
BASELINE_LOG_PATH = "release/0.9.0/current-head/evidence/source-cut-p0r.log.gz"
SOURCE_SIGNATURE = {
    "format": "ssh",
    "status": "verified",
    "principal": "sepmhn@gmail.com",
    "key_fingerprint": "SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU",
}
BASELINE_COMPRESSED_SHA256 = (
    "53d3bcba011be9ac83bbf4975080ff27b33bbf17a99ca2179026e0071ed7f1dc"
)
BASELINE_UNCOMPRESSED_SHA256 = (
    "fbf69d44b56e0abf41ff1efc5bfeced7e3931aff37af05df2d5c1d87a6f07dd8"
)
BASELINE_GATES = (
    "rustfmt",
    "clippy (deny warns)",
    "tests",
    "doc tests",
    "docs (deny warns)",
    "no-default build",
    "default clippy",
    "clean build",
    "dependency policy",
    "source pins",
    "CI/formal pins",
    "release audit tests",
    "release audit cut",
    "release authority tests",
    "release authority model",
    "release evidence generator tests",
    "generated task evidence",
    "release protection tests",
    "release protection model",
    "evidence layout",
    "offline Zenoh profile tests",
    "offline Zenoh profile",
    "retained live Zenoh evidence",
    "forbidden claims",
    "generated vectors",
    "interop (COSE/CBOR)",
    "diff hygiene",
)

EXPECTED_HANDOFF = {
    "archive_sha256": "1de5cfc2a577621c24ef10e97fd2319799d02b602cfb3de54954928a0d988efe",
    "audit_cut_sha256": "b77dcffa56ec0eb0f80fbbd29ff6f7c98ebf8b894e23393f67685b952af80ca6",
    "ledger_sha256": "891601e322f453499fc7a3375728d43f7cfb0eaa193be5b96b1a5d6c7aae0f40",
    "readme_sha256": "bf1d3ea1d830d60a5e8ea9d41b32e5845748165a28d124e52497610b8c3e6f47",
    "sha256s_sha256": "5ed07cc488640d512342c8b3adc1feeda523f897f5f9734cdf62441766d216b0",
}

EXPECTED_SOURCE_FILES = {
    "Cargo.toml": "1712be900a8bab7aa0f5b12a6f1c6d47bbce4078a420936bc598673517f865a2",
    "Cargo.lock": "8767fc69ea7b90b374de6ca77e9d22dbfac0e3b1db236ea03d24f05470d2831f",
    "rust-toolchain.toml": "61d97acc9676fd1b6348a44dee3c372804b9a1e984385c7d73a2620b322d4927",
    "deny.toml": "08e563a6f20d8a5423b0a85a2c2183a9b3d82d0b40ca6efac0ab62976e863ae6",
    "tools/pins.toml": "0cd9c3279c61266c1e926fd1fcce8cd6cab38baf119d1be9e19c7ccc12d7fcb6",
    "deploy/secure-reference-v1/profile.json": "76a10873155ef5fe85f13117fdf6fcb6f3938399823cbb6af9bff523a3b54e06",
    "formal/HaldirAuthority.tla": "0ab0bc5826c356cab6e01555a32fbc489286988b575c62605e740b69c6e5e61e",
    "formal/HaldirAuthority.cfg": "20651c85285170ac0bbd35b6f6b9c31597fd63b28e7678b72388033dbad3c58f",
    ".github/workflows/ci.yml": "171618c83effa8579f492ad79a5e0df0a54a27f72a5b6d8989ffcbc5a5c8180b",
    ".github/workflows/formal.yml": "3de8203531471e675ee03b535fb7c690527a7fd6922a9dd3edb4be32a83443b5",
    "justfile": "4633a855139a3fd799f20f099ed1dc5ab7d5fb6960ceb0880dbd03ef9565c0ca",
    "release/0.9.0/allowed-signers": "88eddddf1b3a6d0176acf2ec88b1d3c120453e2658651c49b82d41057caa78ed",
}

PACKAGE_MANIFESTS = {
    "crates/haldir-admission/Cargo.toml": "haldir-admission",
    "crates/haldir-contracts/Cargo.toml": "haldir-contracts",
    "crates/haldir-core/Cargo.toml": "haldir-core",
    "crates/haldir-crypto/Cargo.toml": "haldir-crypto",
    "crates/haldir-deployment/Cargo.toml": "haldir-deployment",
    "crates/haldir-durable/Cargo.toml": "haldir-durable",
    "crates/haldir-evidence/Cargo.toml": "haldir-evidence",
    "crates/haldir-gate/Cargo.toml": "haldir-gate",
    "crates/haldir-ncp08/Cargo.toml": "haldir-ncp08",
    "crates/haldir-policy-native/Cargo.toml": "haldir-policy-native",
    "crates/haldir-range/Cargo.toml": "haldir-range",
    "crates/haldir-reference-plant/Cargo.toml": "haldir-reference-plant",
    "crates/haldir-state/Cargo.toml": "haldir-state",
    "crates/haldir-testkit/Cargo.toml": "haldir-testkit",
    "crates/haldir-transport-zenoh/Cargo.toml": "haldir-transport-zenoh",
    "tools/haldir-ctl/Cargo.toml": "haldir-ctl",
}

EXPECTED_MASTER_HANDOFF = {
    "prepared": "2026-07-14",
    "checksums_verified": True,
    "master_sha256s_sha256": "0d4d1c19600bd8e5d930cb269fcaa204e80e9728914572664af7961566d3ba57",
    "current_heads_sha256": "dc393b47bac804fa9dd47215e6eced584d0b6863cf57b383ff5957bcbae4bbf6",
    "package_index_sha256": "cec6b200866b0a34473c4429c74137c87790c1fe073a19453ed79e147e32411d",
    "master_validation_sha256": "e693dafd3d53ab031b499f358e3a680a5d2c5fd538023e83fd935f5fd020c777",
    "cross_archive_sha256": "ae06b5525537e88de4ae37aa49b40de01893061bdc3096bcf1059c5c6d71e3d4",
    "cross_sha256s_sha256": "40bd8855cb1ae574d7fb91688d8567a7267089bd80c739c8b1f3270a4efe42f6",
    "cross_ledger_sha256": "807d9e2087e932725513dba0eb0d9de252fed85fcce6b75d0121f252fd08f582",
    "cross_current_heads_sha256": "f43c85b88e71c002ef0f91b2f080526566b3f1e983ae0022f402eadc52efaffa",
    "frozen_heads": {
        "NCP": "0ba5ff6e963225b0635f8fec349278f1ac287df3",
        "crebain": "4c311900ade5668200a48d56fb191be1916b884a",
        "galadriel": "94e2f8cc01f352d2bf899b7f656997f143a2588f",
        "haldir": SOURCE_PARENT,
        "pid-rs": "64060035ea36e380004949f06dd226dcc7242b96",
    },
    "approved_audit_heads": {
        "NCP": "0ba5ff6e963225b0635f8fec349278f1ac287df3",
        "crebain": "4c311900ade5668200a48d56fb191be1916b884a",
        "galadriel": "94e2f8cc01f352d2bf899b7f656997f143a2588f",
        "haldir": SOURCE_COMMIT,
        "pid-rs": "64060035ea36e380004949f06dd226dcc7242b96",
    },
    "other_head_verification_scope": (
        "CHECKSUM_VERIFIED_HANDOFF_ASSERTIONS; NON_HALDIR_GIT_OBJECTS NOT VERIFIED HERE"
    ),
    "child_archives": {
        "NCP": {
            "sha256": "661c5a9bd6a62a8a973bc953fd45ba1a58d44592985c871fc6b039c9cbdd333b",
            "files": 23,
            "tasks": 146,
        },
        "crebain": {
            "sha256": "c7c8a342e5a4b94c2d4c411299c63ed1c01163acff847d9bf7389ed8ea8c052a",
            "files": 23,
            "tasks": 159,
        },
        "galadriel": {
            "sha256": "41bd414e38e7f46a0417005d59e2b0c0eb5e139ec38cce632e006b60a750cd94",
            "files": 23,
            "tasks": 116,
        },
        "haldir": {
            "sha256": EXPECTED_HANDOFF["archive_sha256"],
            "files": 23,
            "tasks": 126,
        },
        "pid-rs": {
            "sha256": "9fcdcaf1e5254942c8dbdf4cea3890f6a858674bd6fd613b14f353b2a60e4730",
            "files": 47,
            "tasks": 159,
        },
    },
    "cross_repo": {"files": 12, "tasks": 79},
    "retained_inputs": [
        {
            "path": "release/0.9.0/current-head/handoff/HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
            "sha256": EXPECTED_HANDOFF["archive_sha256"],
            "bytes": 43_202,
        },
        {
            "path": "release/0.9.0/current-head/handoff/MASTER_CURRENT_HEADS.json",
            "sha256": "dc393b47bac804fa9dd47215e6eced584d0b6863cf57b383ff5957bcbae4bbf6",
            "bytes": 402,
        },
        {
            "path": "release/0.9.0/current-head/handoff/MASTER_SHA256SUMS.txt",
            "sha256": "0d4d1c19600bd8e5d930cb269fcaa204e80e9728914572664af7961566d3ba57",
            "bytes": 1_356,
        },
        {
            "path": "release/0.9.0/current-head/handoff/PACKAGE_INDEX.json",
            "sha256": "cec6b200866b0a34473c4429c74137c87790c1fe073a19453ed79e147e32411d",
            "bytes": 1_345,
        },
        {
            "path": "release/0.9.0/current-head/handoff/SEPAHEAD_V1_0_CURRENT_HEAD_CROSS_REPO_RECONCILIATION_HANDOFF.zip",
            "sha256": "ae06b5525537e88de4ae37aa49b40de01893061bdc3096bcf1059c5c6d71e3d4",
            "bytes": 11_647,
        },
    ],
}

EXPECTED_INPUT_SCOPE = {
    "workspace_packages": {
        "count": 16,
        "source_version": "0.1.0-experimental",
        "registry_publication": False,
        "names": sorted(PACKAGE_MANIFESTS.values()),
    },
    "formal_artifacts": [
        "formal/HaldirAuthority.cfg",
        "formal/HaldirAuthority.tla",
        "formal/README.md",
    ],
    "test_data": [
        "crates/haldir-ncp08/tests/data/ncp-v0.8.0/README.md",
        "crates/haldir-ncp08/tests/data/ncp-v0.8.0/command_frame.json",
        "crates/haldir-ncp08/tests/data/ncp-v0.8.0/command_frame.schema.json",
    ],
    "deployment_profiles": ["deploy/secure-reference-v1/profile.json"],
    "interop_corpora": ["tools/interop/vectors.json"],
    "machine_learning_models": [],
    "papers": [],
    "paper_suffixes_scanned": [".bib", ".pdf", ".tex"],
    "scope_note": (
        "No ML model or paper artifact is tracked; the immutable source tree binds all "
        "other schemas, fixtures, generated evidence, and documentation."
    ),
}

EXPECTED_PUBLICATION_STATE = {
    "local_tags": [],
    "remote_tags": [],
    "github_releases": [],
    "cleanup_disposition": "VERIFIED_NO_OP",
    "evidence": {
        "path": "release/0.9.0/current-head/evidence/publication-state.json",
        "sha256": "2cd20381ce5001bdc36b080bfc0a887b06c6215e3c481a90f351353038e9dba1",
        "bytes": 530,
        "lines": 20,
    },
}

EXPECTED_REQUIREMENTS_LEDGER = {
    "path": "release/0.9.0/current-head/requirements.json",
    "schema_version": "1.0.0",
    "task_namespace": "CH-T000..CH-T125",
    "task_count": 126,
    "identity_sha256": "8b2c92a373514e30c1ab0f5e741ad595c0e3b2e67e37dc660deb43d64a7a6cfb",
    "source_ledger_sha256": EXPECTED_HANDOFF["ledger_sha256"],
    "legacy_ledger_sha256": "04454e6eeba74a1e36fccbfa7110437f3fffb00778ce019819852b7678b04b2d",
}

EXPECTED_GITHUB_CHECKS = {
    "ci": {
        "run_id": 29_327_196_587,
        "workflow": "ci",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_sha": SOURCE_COMMIT,
        "head_branch": "main",
        "created_at": "2026-07-14T10:57:35Z",
        "updated_at": "2026-07-14T10:58:47Z",
        "url": "https://github.com/sepahead/haldir/actions/runs/29327196587",
        "jobs": [
            "interop",
            "macos-compile",
            "supply-chain",
            "feature-matrix",
            "build-test",
            "clean-build",
        ],
        "metadata_evidence": {
            "path": "release/0.9.0/current-head/evidence/source-cut-ci.json",
            "sha256": "55817853d79845b38141f9cc6ca0f25d2c05b9ebff3c815bf153ed625326daf1",
            "bytes": 16_469,
            "lines": 512,
        },
        "log_evidence": {
            "path": "release/0.9.0/current-head/evidence/source-cut-ci.log.gz",
            "compressed_sha256": "c7bd25803990b4bf314b06091f775476fba60b6cde9f83fed2ce11b60c97f6f5",
            "compressed_bytes": 65_961,
            "uncompressed_sha256": "4a5cbf61cb184821332ae851f5c1f57da7f94cb301113ed9b5b58281f3e57794",
            "uncompressed_bytes": 443_370,
            "uncompressed_lines": 3_870,
        },
    },
    "formal": {
        "run_id": 29_327_196_583,
        "workflow": "formal",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_sha": SOURCE_COMMIT,
        "head_branch": "main",
        "created_at": "2026-07-14T10:57:35Z",
        "updated_at": "2026-07-14T10:57:48Z",
        "url": "https://github.com/sepahead/haldir/actions/runs/29327196583",
        "jobs": ["tlc-model-check"],
        "metadata_evidence": {
            "path": "release/0.9.0/current-head/evidence/source-cut-formal.json",
            "sha256": "dd09e6df9702e7017cab4489e0f98b768481d2ae35b01e2d4266acd055789378",
            "bytes": 3_023,
            "lines": 97,
        },
        "log_evidence": {
            "path": "release/0.9.0/current-head/evidence/source-cut-formal.log.gz",
            "compressed_sha256": "854b9eb9c482d43277e1f554e58b875198ce2efad586443466f7bc02666165d7",
            "compressed_bytes": 5_664,
            "uncompressed_sha256": "2e32e702bbe83e4f128e7d12126ae62451ab37e4d7bae86ea7b1b60e712bd00a",
            "uncompressed_bytes": 29_867,
            "uncompressed_lines": 267,
        },
    },
}

EXPECTED_TOP_LEVEL = {
    "schema_version",
    "release_target",
    "captured_at_utc",
    "author",
    "persistent_identifier",
    "source",
    "handoff",
    "master_handoff",
    "input_scope",
    "approved_cut_update",
    "toolchains",
    "locked_inputs",
    "ncp",
    "baseline",
    "requirements_ledger",
    "repository_publication_state",
    "github_source_cut_checks",
}


class CurrentAuditError(ValueError):
    """The current-head audit manifest is malformed or contradicts its cut."""


def _reject_json_constant(value: str) -> None:
    raise CurrentAuditError(f"CURRENT_AUDIT_JSON_CONSTANT_REJECTED:{value}")


def _reject_json_float(value: str) -> None:
    raise CurrentAuditError(f"CURRENT_AUDIT_JSON_FLOAT_REJECTED:{value}")


def _parse_json_int(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > 19:
        raise CurrentAuditError("CURRENT_AUDIT_JSON_INTEGER_OUT_OF_RANGE")
    parsed = int(value)
    if parsed < -(2**63) or parsed > 2**63 - 1:
        raise CurrentAuditError("CURRENT_AUDIT_JSON_INTEGER_OUT_OF_RANGE")
    return parsed


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CurrentAuditError(f"CURRENT_AUDIT_DUPLICATE_JSON_KEY:{key}")
        result[key] = value
    return result


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    if path.is_symlink():
        raise CurrentAuditError(f"CURRENT_AUDIT_SYMLINK_REJECTED:{label}")
    try:
        if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
            raise CurrentAuditError(f"CURRENT_AUDIT_NOT_REGULAR_FILE:{label}")
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
    except OSError as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_READ_FAILED:{label}") from error
    if len(payload) > limit:
        raise CurrentAuditError(f"CURRENT_AUDIT_RESOURCE_BOUND:{label}")
    return payload


def _load_json(
    path: Path, limit: int = MAX_JSON_BYTES, label: str = "manifest"
) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_bounded(path, limit, label),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_parse_json_int,
        )
    except CurrentAuditError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_JSON_INVALID") from error
    if not isinstance(value, dict):
        raise CurrentAuditError("CURRENT_AUDIT_JSON_NOT_OBJECT")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CurrentAuditError(f"CURRENT_AUDIT_INVALID_HEX:{label}")
    return value


def _git(repo: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C"})
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_GIT_FAILED:{' '.join(arguments)}"
        ) from error
    if len(result.stdout) > MAX_GIT_BYTES or len(result.stderr) > MAX_GIT_BYTES:
        raise CurrentAuditError("CURRENT_AUDIT_GIT_OUTPUT_BOUND")
    return result.stdout


def _git_file(repo: Path, commit: str, path: str) -> bytes:
    return _git(repo, "show", f"{commit}:{path}")


def _require_int(value: Any, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise CurrentAuditError(f"CURRENT_AUDIT_INTEGER_INVALID:{label}")


def _strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _strict_equal(item, expected_item)
            for item, expected_item in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


def _reject_symlink_components(repo: Path, path: Path, label: str) -> None:
    try:
        relative = path.relative_to(repo)
    except ValueError as error:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_PATH_OUTSIDE_REPOSITORY:{label}"
        ) from error
    current = repo
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            raise CurrentAuditError(f"CURRENT_AUDIT_SYMLINK_REJECTED:{label}")


def _read_evidence_file(
    repo: Path, record: dict[str, Any], label: str, limit: int
) -> bytes:
    raw_path = record.get("path")
    if not isinstance(raw_path, str):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_INVALID:{label}")
    path = repo / raw_path
    _reject_symlink_components(repo, path, label)
    try:
        if not path.resolve().is_relative_to(repo.resolve()):
            raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_ESCAPE:{label}")
    except OSError as error:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_EVIDENCE_RESOLVE_FAILED:{label}"
        ) from error
    payload = _read_bounded(path, limit, label)
    _require_int(record.get("bytes"), len(payload), f"{label}.bytes")
    if _sha256(payload) != _require_hex(record.get("sha256"), HEX64, label):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_DIGEST_MISMATCH:{label}")
    if "lines" in record:
        _require_int(record.get("lines"), len(payload.splitlines()), f"{label}.lines")
    return payload


def _read_gzip_evidence(
    repo: Path, record: dict[str, Any], label: str, decompressed_limit: int
) -> bytes:
    compressed_record = {
        "path": record.get("path"),
        "sha256": record.get("compressed_sha256"),
        "bytes": record.get("compressed_bytes"),
    }
    compressed = _read_evidence_file(
        repo, compressed_record, f"{label}.gz", MAX_COMPRESSED_LOG_BYTES
    )
    if not compressed.startswith(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03"):
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_HEADER_INVALID:{label}")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as handle:
            payload = handle.read(decompressed_limit + 1)
    except (OSError, EOFError) as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_INVALID:{label}") from error
    if len(payload) > decompressed_limit:
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_RESOURCE_BOUND:{label}")
    _require_int(
        record.get("uncompressed_bytes"), len(payload), f"{label}.uncompressed_bytes"
    )
    _require_int(
        record.get("uncompressed_lines"),
        len(payload.splitlines()),
        f"{label}.uncompressed_lines",
    )
    if _sha256(payload) != _require_hex(
        record.get("uncompressed_sha256"), HEX64, f"{label}.uncompressed"
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_DIGEST_MISMATCH:{label}")
    return payload


def _verify_handoff_zip(payload: bytes, expected_files: int, label: str) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if (
                len(entries) != expected_files
                or len(names) != len(set(names))
                or sum(entry.file_size for entry in entries) > 16 * 1024 * 1024
            ):
                raise CurrentAuditError(f"CURRENT_AUDIT_ZIP_INVENTORY_INVALID:{label}")
            for entry in entries:
                path = PurePosixPath(entry.filename)
                mode = entry.external_attr >> 16
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in entry.filename
                    or entry.is_dir()
                    or entry.file_size > 4 * 1024 * 1024
                    or mode & 0o170000 == 0o120000
                ):
                    raise CurrentAuditError(f"CURRENT_AUDIT_ZIP_ENTRY_INVALID:{label}")
            if archive.testzip() is not None:
                raise CurrentAuditError(f"CURRENT_AUDIT_ZIP_CRC_INVALID:{label}")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_ZIP_INVALID:{label}") from error


def _verify_source_signature(repo: Path) -> None:
    allowed_signers = _git_file(repo, SOURCE_COMMIT, "release/0.9.0/allowed-signers")
    if (
        _sha256(allowed_signers)
        != EXPECTED_SOURCE_FILES["release/0.9.0/allowed-signers"]
    ):
        raise CurrentAuditError("CURRENT_AUDIT_ALLOWED_SIGNERS_MISMATCH")
    try:
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(allowed_signers)
            handle.flush()
            result = subprocess.run(
                [
                    "git",
                    "--no-replace-objects",
                    "-c",
                    f"gpg.ssh.allowedSignersFile={handle.name}",
                    "-c",
                    "gpg.ssh.program=ssh-keygen",
                    "-c",
                    "gpg.format=ssh",
                    "verify-commit",
                    SOURCE_COMMIT,
                ],
                cwd=repo,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
            key_result = subprocess.run(
                ["ssh-keygen", "-E", "sha256", "-lf", handle.name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CurrentAuditError("CURRENT_AUDIT_SIGNATURE_CHECK_FAILED") from error
    output = result.stdout + result.stderr
    key_output = key_result.stdout + key_result.stderr
    if (
        result.returncode != 0
        or key_result.returncode != 0
        or len(output) > MAX_GIT_BYTES
        or len(key_output) > MAX_GIT_BYTES
        or b"sepmhn@gmail.com" not in key_output
        or b"SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU" not in key_output
    ):
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_SIGNATURE_INVALID")


def _source_inventory(repo: Path) -> tuple[int, int, list[str]]:
    entries = _git(repo, "ls-tree", "-r", "-z", "--long", SOURCE_COMMIT).split(b"\0")
    tracked_files = 0
    tracked_bytes = 0
    submodules: list[str] = []
    try:
        for entry in entries:
            if not entry:
                continue
            header, raw_path = entry.split(b"\t", 1)
            _mode, object_type, _object_id, raw_size = header.split()
            tracked_files += 1
            if object_type == b"blob":
                tracked_bytes += int(raw_size)
            elif object_type == b"commit":
                submodules.append(raw_path.decode("utf-8"))
            else:
                raise ValueError("unexpected Git object type")
    except (UnicodeDecodeError, ValueError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_INVENTORY_INVALID") from error
    return tracked_files, tracked_bytes, submodules


def _verify_source(manifest: dict[str, Any], repo: Path) -> None:
    source = manifest.get("source")
    expected_fields = {
        "repository",
        "remote",
        "branch",
        "commit",
        "tree",
        "parent",
        "tree_clean",
        "origin_main_commit",
        "tracked_files",
        "tracked_bytes",
        "submodules",
        "source_commit_signature",
    }
    if not isinstance(source, dict) or set(source) != expected_fields:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_FIELDS_INVALID")
    if (
        source.get("repository") != "https://github.com/sepahead/haldir"
        or source.get("remote") != "git@github.com:sepahead/haldir.git"
        or source.get("branch") != "main"
        or source.get("commit") != SOURCE_COMMIT
        or source.get("tree") != SOURCE_TREE
        or source.get("parent") != SOURCE_PARENT
        or source.get("tree_clean") is not True
        or source.get("origin_main_commit") != SOURCE_COMMIT
        or source.get("tracked_files") != 283
        or source.get("tracked_bytes") != 5_562_467
        or source.get("submodules") != []
        or source.get("source_commit_signature") != SOURCE_SIGNATURE
    ):
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_IDENTITY_INVALID")
    _require_int(source.get("tracked_files"), 283, "source.tracked_files")
    _require_int(source.get("tracked_bytes"), 5_562_467, "source.tracked_bytes")
    actual_tree = _git(repo, "rev-parse", f"{SOURCE_COMMIT}^{{tree}}").decode().strip()
    if actual_tree != SOURCE_TREE:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_TREE_MISMATCH")
    parents = (
        _git(repo, "rev-list", "--parents", "-n", "1", SOURCE_COMMIT).decode().split()
    )
    if parents != [SOURCE_COMMIT, SOURCE_PARENT]:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_PARENT_MISMATCH")
    if _source_inventory(repo) != (283, 5_562_467, []):
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_INVENTORY_MISMATCH")
    _verify_source_signature(repo)


def _verify_handoff(manifest: dict[str, Any]) -> None:
    handoff = manifest.get("handoff")
    expected_fields = {
        "package",
        "prepared",
        "original_release_target",
        "adapted_release_target",
        "original_frozen_commit",
        "task_namespace",
        "original_task_count",
        "checksums_verified",
        *EXPECTED_HANDOFF,
    }
    if not isinstance(handoff, dict) or set(handoff) != expected_fields:
        raise CurrentAuditError("CURRENT_AUDIT_HANDOFF_FIELDS_INVALID")
    if (
        handoff.get("package") != "HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF"
        or handoff.get("prepared") != "2026-07-14"
        or handoff.get("original_release_target") != "1.0.0"
        or handoff.get("adapted_release_target") != "0.9.0"
        or handoff.get("original_frozen_commit") != SOURCE_PARENT
        or handoff.get("task_namespace") != "CH-T000..CH-T125"
        or handoff.get("original_task_count") != 126
        or handoff.get("checksums_verified") is not True
    ):
        raise CurrentAuditError("CURRENT_AUDIT_HANDOFF_IDENTITY_INVALID")
    _require_int(handoff.get("original_task_count"), 126, "handoff.task_count")
    for field, expected in EXPECTED_HANDOFF.items():
        if _require_hex(handoff.get(field), HEX64, field) != expected:
            raise CurrentAuditError(f"CURRENT_AUDIT_HANDOFF_DIGEST_MISMATCH:{field}")


def _verify_master_handoff(manifest: dict[str, Any], repo: Path) -> None:
    master = manifest.get("master_handoff")
    if not _strict_equal(master, EXPECTED_MASTER_HANDOFF):
        raise CurrentAuditError("CURRENT_AUDIT_MASTER_HANDOFF_INVALID")
    for index, record in enumerate(EXPECTED_MASTER_HANDOFF["retained_inputs"]):
        payload = _read_evidence_file(
            repo, record, f"master_handoff[{index}]", 128 * 1024
        )
        if record["path"].endswith("HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip"):
            _verify_handoff_zip(payload, 23, "haldir_handoff")
        elif record["path"].endswith("CROSS_REPO_RECONCILIATION_HANDOFF.zip"):
            _verify_handoff_zip(payload, 12, "cross_repo_handoff")

    heads = _load_json(
        repo / "release/0.9.0/current-head/handoff/MASTER_CURRENT_HEADS.json"
    )
    if not _strict_equal(
        heads,
        {
            "heads": EXPECTED_MASTER_HANDOFF["frozen_heads"],
            "prepared": "2026-07-14",
            "status": "frozen audit cuts; abort and re-audit on change",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_MASTER_HEADS_CONTENT_INVALID")

    package_index = _load_json(
        repo / "release/0.9.0/current-head/handoff/PACKAGE_INDEX.json"
    )
    child_filenames = {
        "NCP": "NCP_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
        "crebain": "CREBAIN_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
        "galadriel": "GALADRIEL_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
        "haldir": "HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
        "pid-rs": "PID_RS_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
    }
    expected_children = {
        name: {"filename": child_filenames[name], **record}
        for name, record in EXPECTED_MASTER_HANDOFF["child_archives"].items()
    }
    if not _strict_equal(
        package_index,
        {
            "children": expected_children,
            "cross_repo": {
                "filename": "SEPAHEAD_V1_0_CURRENT_HEAD_CROSS_REPO_RECONCILIATION_HANDOFF.zip",
                "files": 12,
                "sha256": EXPECTED_MASTER_HANDOFF["cross_archive_sha256"],
                "tasks": 79,
            },
            "prepared": "2026-07-14",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PACKAGE_INDEX_CONTENT_INVALID")


def _verify_input_scope(manifest: dict[str, Any], repo: Path) -> None:
    scope = manifest.get("input_scope")
    if not _strict_equal(scope, EXPECTED_INPUT_SCOPE):
        raise CurrentAuditError("CURRENT_AUDIT_INPUT_SCOPE_INVALID")
    try:
        root_manifest = tomllib.loads(
            _git_file(repo, SOURCE_COMMIT, "Cargo.toml").decode()
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_ROOT_MANIFEST_INVALID") from error
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict):
        raise CurrentAuditError("CURRENT_AUDIT_WORKSPACE_MISSING")
    package_defaults = workspace.get("package")
    if not _strict_equal(
        package_defaults,
        {
            "version": "0.1.0-experimental",
            "edition": "2024",
            "rust-version": "1.96",
            "license": "Apache-2.0 OR MIT",
            "repository": "https://github.com/sepahead/haldir",
            "authors": ["Sepahead"],
            "publish": False,
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_WORKSPACE_DEFAULTS_INVALID")
    if set(workspace.get("members", [])) != {
        path.removesuffix("/Cargo.toml") for path in PACKAGE_MANIFESTS
    }:
        raise CurrentAuditError("CURRENT_AUDIT_WORKSPACE_MEMBERS_INVALID")
    for path, expected_name in PACKAGE_MANIFESTS.items():
        try:
            member = tomllib.loads(_git_file(repo, SOURCE_COMMIT, path).decode())
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_PACKAGE_MANIFEST_INVALID:{path}"
            ) from error
        package = member.get("package")
        if not isinstance(package, dict) or (
            package.get("name") != expected_name
            or package.get("version") != {"workspace": True}
            or package.get("authors") != {"workspace": True}
            or package.get("publish") != {"workspace": True}
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_PACKAGE_IDENTITY_INVALID:{path}")

    tree_paths = set(
        _git(repo, "ls-tree", "-r", "--name-only", SOURCE_COMMIT).decode().splitlines()
    )
    declared_paths = (
        EXPECTED_INPUT_SCOPE["formal_artifacts"]
        + EXPECTED_INPUT_SCOPE["test_data"]
        + EXPECTED_INPUT_SCOPE["deployment_profiles"]
        + EXPECTED_INPUT_SCOPE["interop_corpora"]
    )
    if any(path not in tree_paths for path in declared_paths):
        raise CurrentAuditError("CURRENT_AUDIT_DECLARED_INPUT_MISSING")
    if any(
        path.lower().endswith(tuple(EXPECTED_INPUT_SCOPE["paper_suffixes_scanned"]))
        for path in tree_paths
    ):
        raise CurrentAuditError("CURRENT_AUDIT_UNRECORDED_PAPER_FOUND")
    if any(
        path.lower().endswith(
            (".onnx", ".pb", ".pt", ".pth", ".safetensors", ".tflite")
        )
        for path in tree_paths
    ):
        raise CurrentAuditError("CURRENT_AUDIT_UNRECORDED_ML_MODEL_FOUND")


def _verify_cut_update(manifest: dict[str, Any], repo: Path) -> None:
    update = manifest.get("approved_cut_update")
    if not isinstance(update, dict):
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_INVALID")
    if update != {
        "status": "LEAD_APPROVED_AFTER_COMPLETE_DIFF_AND_REBASELINE",
        "from_commit": SOURCE_PARENT,
        "to_commit": SOURCE_COMMIT,
        "commit_count": 1,
        "insertions": 340,
        "deletions": 58,
        "patch_sha256": "621264b02620212b5cf2255cfc37c492f66f2d52160e14f2e7ff464e44cee413",
        "files": [
            {
                "path": "docs/THREAT-MODEL.md",
                "change": "modified",
                "sha256": "b5d7b83d29a95a58cb2c8d3ecfa470db0c2d8b76e09abed5e9af58ee00abb70b",
            },
            {
                "path": "docs/release/0.9.0/THREAT-MODEL.md",
                "change": "added",
                "sha256": "cd7010762be3bc3cd278d932fa1e3f0c8014d5277799405822148c28bdeffbc0",
            },
        ],
    }:
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_RECORD_MISMATCH")
    _require_int(update.get("commit_count"), 1, "approved_cut_update.commit_count")
    _require_int(update.get("insertions"), 340, "approved_cut_update.insertions")
    _require_int(update.get("deletions"), 58, "approved_cut_update.deletions")
    commit_count = (
        _git(repo, "rev-list", "--count", f"{SOURCE_PARENT}..{SOURCE_COMMIT}")
        .decode()
        .strip()
    )
    if commit_count != "1":
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_COMMIT_COUNT_MISMATCH")
    name_status = (
        _git(
            repo,
            "diff",
            "--no-renames",
            "--no-color",
            "--name-status",
            f"{SOURCE_PARENT}..{SOURCE_COMMIT}",
        )
        .decode()
        .splitlines()
    )
    if name_status != [
        "M\tdocs/THREAT-MODEL.md",
        "A\tdocs/release/0.9.0/THREAT-MODEL.md",
    ]:
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_DIFF_MISMATCH")
    numstat = (
        _git(
            repo,
            "-c",
            "diff.algorithm=myers",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--no-color",
            "--numstat",
            f"{SOURCE_PARENT}..{SOURCE_COMMIT}",
        )
        .decode()
        .splitlines()
    )
    if numstat != [
        "19\t58\tdocs/THREAT-MODEL.md",
        "321\t0\tdocs/release/0.9.0/THREAT-MODEL.md",
    ]:
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_NUMSTAT_MISMATCH")
    patch = _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--binary",
        "--full-index",
        f"{SOURCE_PARENT}..{SOURCE_COMMIT}",
    )
    if _sha256(patch) != update["patch_sha256"]:
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_PATCH_MISMATCH")
    for record in update["files"]:
        if _sha256(_git_file(repo, SOURCE_COMMIT, record["path"])) != record["sha256"]:
            raise CurrentAuditError("CURRENT_AUDIT_UPDATE_FILE_MISMATCH")


def _verify_locked_inputs(manifest: dict[str, Any], repo: Path) -> None:
    locked = manifest.get("locked_inputs")
    if not isinstance(locked, list) or len(locked) != len(EXPECTED_SOURCE_FILES):
        raise CurrentAuditError("CURRENT_AUDIT_LOCKED_INPUTS_INVALID")
    observed: dict[str, str] = {}
    for record in locked:
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            raise CurrentAuditError("CURRENT_AUDIT_LOCKED_INPUT_ENTRY_INVALID")
        path = record.get("path")
        digest = _require_hex(record.get("sha256"), HEX64, "locked_input")
        if not isinstance(path, str) or path in observed:
            raise CurrentAuditError("CURRENT_AUDIT_LOCKED_INPUT_DUPLICATE")
        observed[path] = digest
    if observed != EXPECTED_SOURCE_FILES:
        raise CurrentAuditError("CURRENT_AUDIT_LOCKED_INPUT_SET_MISMATCH")
    for path, expected in observed.items():
        if _sha256(_git_file(repo, SOURCE_COMMIT, path)) != expected:
            raise CurrentAuditError(f"CURRENT_AUDIT_LOCKED_INPUT_MISMATCH:{path}")


def _verify_requirements_ledger(manifest: dict[str, Any], repo: Path) -> None:
    record = manifest.get("requirements_ledger")
    if not _strict_equal(record, EXPECTED_REQUIREMENTS_LEDGER):
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_RECORD_INVALID")
    ledger = _load_json(
        repo / EXPECTED_REQUIREMENTS_LEDGER["path"],
        MAX_REQUIREMENTS_BYTES,
        "requirements",
    )
    expected_top_level = {
        "schema_version",
        "project",
        "release_target",
        "author",
        "persistent_identifier",
        "source_handoff",
        "approved_cut",
        "legacy_ledger",
        "task_identity",
        "overall_status",
        "tasks",
    }
    if set(ledger) != expected_top_level:
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_FIELDS_INVALID")
    expected_metadata = {
        "schema_version": "1.0.0",
        "project": "Haldir",
        "release_target": "0.9.0",
        "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
        "persistent_identifier": None,
        "source_handoff": {
            "archive_path": "release/0.9.0/current-head/handoff/HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
            "archive_sha256": EXPECTED_HANDOFF["archive_sha256"],
            "ledger_path_in_archive": "MASTER_TASK_LEDGER.yaml",
            "ledger_sha256": EXPECTED_HANDOFF["ledger_sha256"],
            "original_release_target": "1.0.0",
            "original_frozen_commit": SOURCE_PARENT,
        },
        "approved_cut": {
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
            "errata_path": "release/0.9.0/current-head/HANDOFF-ERRATA.md",
        },
        "legacy_ledger": {
            "path": "release/0.9.0/requirements.json",
            "source_commit_sha256": EXPECTED_REQUIREMENTS_LEDGER[
                "legacy_ledger_sha256"
            ],
            "task_namespace": "T000..T119",
            "task_count": 120,
            "closure_transfer_permitted": False,
        },
        "task_identity": {
            "namespace": "CH-T000..CH-T125",
            "count": 126,
            "dependency_model": "STRICT_SINGLE_CHAIN",
            "source_ids_preserved": True,
            "closure_requires_all_twenty_lenses": True,
        },
    }
    for key, expected in expected_metadata.items():
        if not _strict_equal(ledger.get(key), expected):
            raise CurrentAuditError(f"CURRENT_AUDIT_REQUIREMENTS_METADATA:{key}")
    if ledger.get("overall_status") != "NO_GO":
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_OVERALL_STATUS_INVALID")
    tasks = ledger.get("tasks")
    if not isinstance(tasks, list) or len(tasks) != 126:
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_TASK_COUNT_INVALID")
    identity_fields = (
        "id",
        "source_task_id",
        "source_record_sha256",
        "phase",
        "title",
        "source_scope",
        "focus",
        "priority",
        "dependencies",
        "execution_wave",
        "subagent_lane",
        "lead_review_required",
    )
    mutable_fields = {
        "status",
        "claim_disposition",
        "assigned_reviewers",
        "implementation_commits",
        "evidence",
        "closure_commit",
        "twenty_lens_reviews",
    }
    identities: list[dict[str, Any]] = []
    expected_mutable_state = {
        "status": "OPEN",
        "claim_disposition": "UNRESOLVED",
        "assigned_reviewers": [],
        "implementation_commits": [],
        "evidence": [],
        "closure_commit": None,
        "twenty_lens_reviews": {},
    }
    for index, task in enumerate(tasks):
        if (
            not isinstance(task, dict)
            or set(task) != set(identity_fields) | mutable_fields
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_REQUIREMENTS_TASK_FIELDS:{index}")
        expected_id = f"CH-T{index:03d}"
        expected_source_id = f"T{index:03d}"
        expected_dependencies = [] if index == 0 else [f"CH-T{index - 1:03d}"]
        if (
            task.get("id") != expected_id
            or task.get("source_task_id") != expected_source_id
            or task.get("dependencies") != expected_dependencies
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REQUIREMENTS_TASK_INVALID:{expected_id}"
            )
        _require_hex(task.get("source_record_sha256"), HEX64, expected_id)
        if not _strict_equal(
            {field: task[field] for field in mutable_fields}, expected_mutable_state
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REQUIREMENTS_BOOTSTRAP_STATE_INVALID:{expected_id}"
            )
        identities.append({field: task[field] for field in identity_fields})
    identity_payload = json.dumps(
        identities, sort_keys=True, separators=(",", ":")
    ).encode()
    if _sha256(identity_payload) != EXPECTED_REQUIREMENTS_LEDGER["identity_sha256"]:
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_IDENTITY_MISMATCH")


def _verify_baseline(manifest: dict[str, Any], repo: Path) -> None:
    baseline = manifest.get("baseline")
    if not isinstance(baseline, dict) or set(baseline) != {
        "source_commit",
        "command",
        "exit_status",
        "passed_gates",
        "failed_gates",
        "log",
    }:
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_INVALID")
    if (
        baseline.get("source_commit") != SOURCE_COMMIT
        or baseline.get("command") != "bash tools/p0r-exit-gate.sh"
        or baseline.get("exit_status") != 0
        or baseline.get("passed_gates") != 27
        or baseline.get("failed_gates") != 0
    ):
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_RESULT_INVALID")
    _require_int(baseline.get("exit_status"), 0, "baseline.exit_status")
    _require_int(baseline.get("passed_gates"), 27, "baseline.passed_gates")
    _require_int(baseline.get("failed_gates"), 0, "baseline.failed_gates")
    log = baseline.get("log")
    if not isinstance(log, dict) or set(log) != {
        "path",
        "compressed_sha256",
        "compressed_bytes",
        "uncompressed_sha256",
        "uncompressed_bytes",
        "uncompressed_lines",
    }:
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_LOG_RECORD_INVALID")
    if log != {
        "path": BASELINE_LOG_PATH,
        "compressed_sha256": BASELINE_COMPRESSED_SHA256,
        "compressed_bytes": 20_018,
        "uncompressed_sha256": BASELINE_UNCOMPRESSED_SHA256,
        "uncompressed_bytes": 130_401,
        "uncompressed_lines": 2_409,
    }:
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_LOG_RECORD_MISMATCH")
    _require_int(log.get("compressed_bytes"), 20_018, "baseline.log.compressed_bytes")
    _require_int(
        log.get("uncompressed_bytes"), 130_401, "baseline.log.uncompressed_bytes"
    )
    _require_int(log.get("uncompressed_lines"), 2_409, "baseline.log.lines")
    payload = _read_gzip_evidence(repo, log, "baseline.log", MAX_LOG_BYTES)
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_LOG_NOT_UTF8") from error
    passed = [
        line.removeprefix("  PASS: ") for line in lines if line.startswith("  PASS: ")
    ]
    failed = [line for line in lines if line.startswith("  FAIL: ")]
    if (
        len(payload) != log.get("uncompressed_bytes")
        or len(payload.splitlines()) != log.get("uncompressed_lines")
        or _sha256(payload)
        != _require_hex(log.get("uncompressed_sha256"), HEX64, "baseline.log")
        or passed != list(BASELINE_GATES)
        or failed
        or payload.count(b"P0-R exit gate: 27 passed, 0 failed") != 1
        or not payload.rstrip().endswith(
            b"All offline P0-R gates passed. (TLA+ check runs in CI: CL-FORMAL-01.)"
        )
    ):
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_LOG_MISMATCH")


def _verify_publication_state(manifest: dict[str, Any], repo: Path) -> None:
    publication = manifest.get("repository_publication_state")
    if not _strict_equal(publication, EXPECTED_PUBLICATION_STATE):
        raise CurrentAuditError("CURRENT_AUDIT_PUBLICATION_STATE_INVALID")
    _read_evidence_file(
        repo,
        EXPECTED_PUBLICATION_STATE["evidence"],
        "publication_state",
        MAX_JSON_BYTES,
    )
    raw = _load_json(repo / EXPECTED_PUBLICATION_STATE["evidence"]["path"])
    if not _strict_equal(
        raw,
        {
            "captured_at_utc": "2026-07-14T14:47:49Z",
            "cleanup_disposition": "VERIFIED_NO_OP",
            "github_releases": {
                "command": "gh release list --repo sepahead/haldir --limit 100 --json tagName,name,isDraft,isPrerelease,publishedAt",
                "exit_status": 0,
                "values": [],
            },
            "local_tags": {
                "command": "git tag --list",
                "exit_status": 0,
                "values": [],
            },
            "remote_tags": {
                "command": "gh api --paginate repos/sepahead/haldir/tags",
                "exit_status": 0,
                "values": [],
            },
            "schema_version": "1.0.0",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PUBLICATION_EVIDENCE_INVALID")


def _verify_github_checks(manifest: dict[str, Any], repo: Path) -> None:
    checks = manifest.get("github_source_cut_checks")
    if not _strict_equal(checks, EXPECTED_GITHUB_CHECKS):
        raise CurrentAuditError("CURRENT_AUDIT_GITHUB_CHECKS_INVALID")
    for label, expected in EXPECTED_GITHUB_CHECKS.items():
        _read_evidence_file(
            repo,
            expected["metadata_evidence"],
            f"github.{label}.metadata",
            MAX_JSON_BYTES,
        )
        raw = _load_json(repo / expected["metadata_evidence"]["path"])
        expected_fields = {
            "conclusion",
            "createdAt",
            "databaseId",
            "event",
            "headBranch",
            "headSha",
            "jobs",
            "status",
            "updatedAt",
            "url",
            "workflowName",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise CurrentAuditError(f"CURRENT_AUDIT_GITHUB_METADATA_FIELDS:{label}")
        if not _strict_equal(
            {key: raw[key] for key in expected_fields - {"jobs"}},
            {
                "conclusion": expected["conclusion"],
                "createdAt": expected["created_at"],
                "databaseId": expected["run_id"],
                "event": expected["event"],
                "headBranch": expected["head_branch"],
                "headSha": expected["head_sha"],
                "status": expected["status"],
                "updatedAt": expected["updated_at"],
                "url": expected["url"],
                "workflowName": expected["workflow"],
            },
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_GITHUB_METADATA_MISMATCH:{label}")
        jobs = raw.get("jobs")
        if (
            not isinstance(jobs, list)
            or [job.get("name") for job in jobs] != expected["jobs"]
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_GITHUB_JOBS_INVALID:{label}")
        for job in jobs:
            if (
                not isinstance(job, dict)
                or job.get("status") != "completed"
                or job.get("conclusion") != "success"
                or not isinstance(job.get("steps"), list)
                or any(step.get("conclusion") != "success" for step in job["steps"])
            ):
                raise CurrentAuditError(f"CURRENT_AUDIT_GITHUB_JOB_FAILED:{label}")
        _read_gzip_evidence(
            repo,
            expected["log_evidence"],
            f"github.{label}.log",
            MAX_LOG_BYTES,
        )


def verify(manifest_path: Path, repo: Path) -> None:
    """Verify ``manifest_path`` against immutable objects available in ``repo``."""

    manifest = _load_json(manifest_path)
    if set(manifest) != EXPECTED_TOP_LEVEL:
        raise CurrentAuditError("CURRENT_AUDIT_TOP_LEVEL_FIELDS_INVALID")
    if (
        manifest.get("schema_version") != "2.0.0"
        or manifest.get("release_target") != "0.9.0"
    ):
        raise CurrentAuditError("CURRENT_AUDIT_VERSION_INVALID")
    if manifest.get("captured_at_utc") != CAPTURED_AT_UTC:
        raise CurrentAuditError("CURRENT_AUDIT_CAPTURE_TIME_INVALID")
    if manifest.get("author") != {
        "name": "Sepehr Mahmoudian",
        "email": "sepmhn@gmail.com",
    }:
        raise CurrentAuditError("CURRENT_AUDIT_AUTHOR_INVALID")
    if manifest.get("persistent_identifier") is not None:
        raise CurrentAuditError("CURRENT_AUDIT_PERSISTENT_IDENTIFIER_MUST_BE_ABSENT")
    _verify_source(manifest, repo)
    _verify_handoff(manifest)
    _verify_master_handoff(manifest, repo)
    _verify_input_scope(manifest, repo)
    _verify_cut_update(manifest, repo)
    _verify_locked_inputs(manifest, repo)
    _verify_requirements_ledger(manifest, repo)
    _verify_baseline(manifest, repo)
    _verify_publication_state(manifest, repo)
    _verify_github_checks(manifest, repo)
    ncp = manifest.get("ncp")
    if not _strict_equal(
        ncp,
        {
            "protocol": "0.8",
            "package_version": "0.8.0",
            "commit": "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e",
            "protocol_1_0_qualified": False,
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_NCP_RECORD_INVALID")
    if not _strict_equal(
        manifest.get("toolchains"),
        {
            "rustc": "1.96.0 (ac68faa20 2026-05-25)",
            "cargo": "1.96.0 (30a34c682 2026-05-25)",
            "python": "3.14.6",
            "cargo_deny": "0.19.9",
            "host": "aarch64-apple-darwin",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_TOOLCHAINS_INVALID")


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    manifest = repo / "release/0.9.0/current-head/audit-inputs.json"
    try:
        verify(manifest, repo)
    except CurrentAuditError as error:
        print(f"verify-current-audit: FAIL: {error}", file=sys.stderr)
        return 1
    print("verify-current-audit: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
