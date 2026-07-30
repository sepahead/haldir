#!/usr/bin/env python3
"""Validate and install Haldir's exact cargo-deny supply-chain inputs.

The repository verifier calls :func:`verify_repository_policy`, so the
protected ``Verify source pins`` CI step rejects schema, workflow, binary, and
RustSec snapshot drift. Installation is deliberately offline: callers fetch
archives separately, then this module verifies exact sizes and digests, parses
closed bounded tar layouts without ``extractall``, verifies the binary, and
seeds cargo-deny's canonical advisory-database path as an exact Git tree.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import io
import os
import platform
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tarfile
import tomllib
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
PIN_SCHEMA_VERSION = 1
MAX_POLICY_BYTES = 64 * 1024
MAX_WORKFLOW_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 8_000_000
MAX_TAR_BYTES = 12_000_000
MAX_BINARY_BYTES = 10_000_000
MAX_ARCHIVE_MEMBERS = 5
MAX_MEMBER_NAME_BYTES = 256
MAX_ADVISORY_ARCHIVE_BYTES = 1_000_000
MAX_ADVISORY_TAR_BYTES = 4_000_000
MAX_ADVISORY_MEMBERS = 4_096
MAX_ADVISORY_MEMBER_BYTES = 64 * 1024
MAX_ADVISORY_WORKTREE_BYTES = 2_000_000
MAX_GIT_OUTPUT_BYTES = 16 * 1024
GIT_TIMEOUT_SECONDS = 30
VERSION_TIMEOUT_SECONDS = 10
CHECKSUM = re.compile(r"[0-9a-f]{64}")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
EXACT_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
FORBIDDEN_ACTION_REPOSITORY = "EmbarkStudios/cargo-deny-action"
RUSTSEC_REPOSITORY_URL = "https://github.com/RustSec/advisory-db"
RUSTSEC_DATABASE_DIRECTORY = "advisory-db-3157b0e258782691"
RUSTSEC_MAXIMUM_STALENESS_DAYS = 90
SEED_IDENTITY = "Haldir RustSec Snapshot <rustsec-snapshot@haldir.invalid>"
SUPPORTED_TARGETS = frozenset(
    {
        "aarch64-apple-darwin",
        "x86_64-unknown-linux-musl",
    }
)
TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "toolchain",
        "ncp",
        "zenoh",
        "live_transport",
        "dependencies",
        "supply_chain",
        "formal",
    }
)
TABLE_KEYS = {
    "toolchain": frozenset({"rust_channel", "edition", "components"}),
    "ncp": frozenset(
        {
            "tag",
            "commit",
            "wire_version",
            "contract_hash",
            "proto_sha256",
            "command_vector_sha256",
            "command_schema_sha256",
            "enabled_increment",
            "capability_profile",
        }
    ),
    "zenoh": frozenset({"version", "default_features", "features"}),
    "live_transport": frozenset({"probe_builder_image", "router_image"}),
    "dependencies": frozenset(
        {
            "ed25519-compact",
            "sha2",
            "zeroize",
            "subtle",
            "getrandom",
            "proptest",
            "rustix",
            "ncp-core",
            "serde_json",
            "hmac",
            "tokio",
            "zenoh",
        }
    ),
    "supply_chain": frozenset({"cargo_deny"}),
    "formal": frozenset({"tla_tools_version", "tla_tools_sha256"}),
}
CARGO_DENY_KEYS = frozenset(
    {
        "version",
        "advisory_db",
        "assets",
    }
)
ADVISORY_DB_KEYS = frozenset(
    {
        "repository_url",
        "archive_url",
        "commit",
        "committed_at",
        "tree",
        "seed_commit",
        "database_directory",
        "maximum_staleness_days",
        "archive_bytes",
        "archive_sha256",
        "tar_bytes",
        "tar_sha256",
        "member_count",
        "regular_file_count",
        "directory_count",
        "worktree_bytes",
    }
)
ASSET_KEYS = frozenset(
    {
        "target",
        "url",
        "archive_bytes",
        "archive_sha256",
        "binary_bytes",
        "binary_sha256",
    }
)
ANCILLARY_FILES = {
    "LICENSE-APACHE": 0o644,
    "LICENSE-MIT": 0o644,
    "README.md": 0o644,
}


class PinPolicyError(RuntimeError):
    """A deterministic cargo-deny pin or archive-policy violation."""


class CargoDenyAsset(NamedTuple):
    """One exact official release asset."""

    target: str
    url: str
    archive_bytes: int
    archive_sha256: str
    binary_bytes: int
    binary_sha256: str


class RustSecSnapshot(NamedTuple):
    """One exact official RustSec advisory-database snapshot."""

    repository_url: str
    archive_url: str
    commit: str
    committed_at: str
    tree: str
    seed_commit: str
    database_directory: str
    maximum_staleness_days: int
    archive_bytes: int
    archive_sha256: str
    tar_bytes: int
    tar_sha256: str
    member_count: int
    regular_file_count: int
    directory_count: int
    worktree_bytes: int


class CargoDenyPolicy(NamedTuple):
    """The closed cargo-deny policy parsed from ``tools/pins.toml``."""

    version: str
    advisory_db: RustSecSnapshot
    assets: tuple[CargoDenyAsset, ...]

    def asset_for(self, target: str) -> CargoDenyAsset:
        """Return the sole asset for ``target``."""

        matches = [asset for asset in self.assets if asset.target == target]
        require(len(matches) == 1, f"no unique cargo-deny asset for {target!r}")
        return matches[0]


def require(condition: bool, message: str) -> None:
    """Raise :class:`PinPolicyError` when ``condition`` is false."""

    if not condition:
        raise PinPolicyError(message)


def _require_exact_keys(value: Any, expected: frozenset[str], label: str) -> None:
    require(type(value) is dict, f"{label} must be a table")
    observed = set(value)
    missing = sorted(expected - observed)
    unknown = sorted(observed - expected)
    require(
        not missing and not unknown,
        f"{label} schema differs: missing={missing!r}, unknown={unknown!r}",
    )


def _bounded_regular_bytes(path: Path, maximum: int, label: str) -> bytes:
    """Read one non-symlink regular file through a bounded descriptor."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    require(no_follow is not None, "this platform lacks O_NOFOLLOW")
    try:
        descriptor = os.open(path, flags | no_follow)
    except OSError as error:
        raise PinPolicyError(f"cannot open {label} as a regular file") from error
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
        require(
            0 < metadata.st_size <= maximum,
            f"{label} violates its {maximum}-byte bound",
        )
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            require(chunk != b"", f"{label} was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(os.read(descriptor, 1) == b"", f"{label} grew while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _decode_utf8(payload: bytes, label: str) -> str:
    require(b"\0" not in payload, f"{label} contains a NUL byte")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PinPolicyError(f"{label} is not valid UTF-8") from error


def read_pins(root: Path) -> dict[str, Any]:
    """Read the bounded, regular repository pin file."""

    path = root / "tools" / "pins.toml"
    payload = _bounded_regular_bytes(path, MAX_POLICY_BYTES, "tools/pins.toml")
    try:
        pins = tomllib.loads(_decode_utf8(payload, "tools/pins.toml"))
    except tomllib.TOMLDecodeError as error:
        raise PinPolicyError(f"tools/pins.toml is invalid TOML: {error}") from error
    require(type(pins) is dict, "tools/pins.toml must contain a table")
    return pins


def _parse_committed_at(value: Any) -> dt.datetime:
    """Parse one canonical, second-resolution, offset-aware timestamp."""

    require(
        isinstance(value, str)
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
            r"[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}",
            value,
        )
        is not None,
        "supply_chain.cargo_deny.advisory_db.committed_at is not canonical",
    )
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as error:
        raise PinPolicyError(
            "supply_chain.cargo_deny.advisory_db.committed_at is invalid"
        ) from error
    require(
        parsed.tzinfo is not None
        and parsed.utcoffset() is not None
        and parsed.isoformat(timespec="seconds") == value,
        "supply_chain.cargo_deny.advisory_db.committed_at is not canonical",
    )
    return parsed


def _seed_commit_payload(
    *,
    commit: str,
    tree: str,
    committed_at: str,
) -> bytes:
    """Return the deterministic synthetic Git commit for one exact tree."""

    parsed = _parse_committed_at(committed_at)
    timestamp = int(parsed.timestamp())
    offset = parsed.strftime("%z")
    return (
        f"tree {tree}\n"
        f"author {SEED_IDENTITY} {timestamp} {offset}\n"
        f"committer {SEED_IDENTITY} {timestamp} {offset}\n"
        "\n"
        f"RustSec advisory-db snapshot {commit}\n"
    ).encode("utf-8")


def _git_object_id(kind: str, payload: bytes) -> str:
    """Compute Git's SHA-1 object identity for deterministic seed checks."""

    framed = kind.encode("ascii") + b" " + str(len(payload)).encode("ascii")
    return hashlib.sha1(
        framed + b"\0" + payload,
        usedforsecurity=False,
    ).hexdigest()


def _parse_advisory_snapshot(value: Any) -> RustSecSnapshot:
    """Validate and return the closed RustSec snapshot record."""

    label = "supply_chain.cargo_deny.advisory_db"
    _require_exact_keys(value, ADVISORY_DB_KEYS, label)
    commit = value["commit"]
    tree = value["tree"]
    seed_commit = value["seed_commit"]
    for field, item in (
        ("commit", commit),
        ("tree", tree),
        ("seed_commit", seed_commit),
    ):
        require(
            isinstance(item, str) and FULL_SHA.fullmatch(item) is not None,
            f"{label}.{field} must be a full SHA-1",
        )
    repository_url = value["repository_url"]
    archive_url = value["archive_url"]
    require(
        repository_url == RUSTSEC_REPOSITORY_URL,
        f"{label}.repository_url is not the official cargo-deny default",
    )
    require(
        archive_url
        == f"https://codeload.github.com/RustSec/advisory-db/tar.gz/{commit}",
        f"{label}.archive_url is not canonical",
    )
    committed_at = value["committed_at"]
    _parse_committed_at(committed_at)
    require(
        value["database_directory"] == RUSTSEC_DATABASE_DIRECTORY,
        f"{label}.database_directory is not cargo-deny's canonical URL mapping",
    )
    require(
        type(value["maximum_staleness_days"]) is int
        and value["maximum_staleness_days"] == RUSTSEC_MAXIMUM_STALENESS_DAYS,
        f"{label}.maximum_staleness_days must be {RUSTSEC_MAXIMUM_STALENESS_DAYS}",
    )
    integer_bounds = {
        "archive_bytes": MAX_ADVISORY_ARCHIVE_BYTES,
        "tar_bytes": MAX_ADVISORY_TAR_BYTES,
        "member_count": MAX_ADVISORY_MEMBERS,
        "regular_file_count": MAX_ADVISORY_MEMBERS,
        "directory_count": MAX_ADVISORY_MEMBERS,
        "worktree_bytes": MAX_ADVISORY_WORKTREE_BYTES,
    }
    for field, maximum in integer_bounds.items():
        item = value[field]
        require(
            type(item) is int and 0 < item <= maximum,
            f"{label}.{field} violates the hard bound",
        )
    require(
        value["member_count"] == value["regular_file_count"] + value["directory_count"],
        f"{label} member counts are inconsistent",
    )
    for field in ("archive_sha256", "tar_sha256"):
        item = value[field]
        require(
            isinstance(item, str) and CHECKSUM.fullmatch(item) is not None,
            f"{label}.{field} is not exact",
        )
    payload = _seed_commit_payload(
        commit=commit,
        tree=tree,
        committed_at=committed_at,
    )
    require(
        hmac.compare_digest(_git_object_id("commit", payload), seed_commit),
        f"{label}.seed_commit differs from the deterministic seed",
    )
    return RustSecSnapshot(
        repository_url=repository_url,
        archive_url=archive_url,
        commit=commit,
        committed_at=committed_at,
        tree=tree,
        seed_commit=seed_commit,
        database_directory=value["database_directory"],
        maximum_staleness_days=value["maximum_staleness_days"],
        archive_bytes=value["archive_bytes"],
        archive_sha256=value["archive_sha256"],
        tar_bytes=value["tar_bytes"],
        tar_sha256=value["tar_sha256"],
        member_count=value["member_count"],
        regular_file_count=value["regular_file_count"],
        directory_count=value["directory_count"],
        worktree_bytes=value["worktree_bytes"],
    )


def parse_policy(pins: Mapping[str, Any]) -> CargoDenyPolicy:
    """Validate the complete closed pin schema and return cargo-deny pins."""

    _require_exact_keys(pins, TOP_LEVEL_KEYS, "tools/pins.toml")
    require(
        type(pins["schema_version"]) is int
        and pins["schema_version"] == PIN_SCHEMA_VERSION,
        f"tools/pins.toml schema_version must be {PIN_SCHEMA_VERSION}",
    )
    for table, expected in TABLE_KEYS.items():
        _require_exact_keys(pins[table], expected, table)
    dependencies = pins["dependencies"]
    for name, value in dependencies.items():
        require(
            type(value) is str and 0 < len(value) <= 128,
            f"dependencies.{name} must be a bounded string pin",
        )
    require(
        dependencies["rustix"] == "1.1.4",
        "dependencies.rustix must be the exact direct dependency pin",
    )

    cargo_deny = pins["supply_chain"]["cargo_deny"]
    _require_exact_keys(cargo_deny, CARGO_DENY_KEYS, "supply_chain.cargo_deny")
    version = cargo_deny["version"]
    require(
        isinstance(version, str) and EXACT_VERSION.fullmatch(version) is not None,
        "supply_chain.cargo_deny.version must be an exact release",
    )
    advisory_db = _parse_advisory_snapshot(cargo_deny["advisory_db"])

    records = cargo_deny["assets"]
    require(
        isinstance(records, list) and len(records) == len(SUPPORTED_TARGETS),
        "supply_chain.cargo_deny.assets must cover the supported targets exactly",
    )
    assets: list[CargoDenyAsset] = []
    observed_targets: set[str] = set()
    for index, record in enumerate(records):
        label = f"supply_chain.cargo_deny.assets[{index}]"
        _require_exact_keys(record, ASSET_KEYS, label)
        target = record["target"]
        require(
            isinstance(target, str) and target in SUPPORTED_TARGETS,
            f"{label}.target is unsupported",
        )
        require(target not in observed_targets, f"duplicate cargo-deny target {target}")
        observed_targets.add(target)
        expected_url = (
            "https://github.com/EmbarkStudios/cargo-deny/releases/download/"
            f"{version}/cargo-deny-{version}-{target}.tar.gz"
        )
        require(record["url"] == expected_url, f"{label}.url is not canonical")

        archive_bytes = record["archive_bytes"]
        binary_bytes = record["binary_bytes"]
        require(
            type(archive_bytes) is int and 0 < archive_bytes <= MAX_ARCHIVE_BYTES,
            f"{label}.archive_bytes violates the hard bound",
        )
        require(
            type(binary_bytes) is int and 0 < binary_bytes <= MAX_BINARY_BYTES,
            f"{label}.binary_bytes violates the hard bound",
        )
        archive_sha256 = record["archive_sha256"]
        binary_sha256 = record["binary_sha256"]
        require(
            isinstance(archive_sha256, str)
            and CHECKSUM.fullmatch(archive_sha256) is not None,
            f"{label}.archive_sha256 is not exact",
        )
        require(
            isinstance(binary_sha256, str)
            and CHECKSUM.fullmatch(binary_sha256) is not None,
            f"{label}.binary_sha256 is not exact",
        )
        assets.append(
            CargoDenyAsset(
                target=target,
                url=expected_url,
                archive_bytes=archive_bytes,
                archive_sha256=archive_sha256,
                binary_bytes=binary_bytes,
                binary_sha256=binary_sha256,
            )
        )
    require(
        observed_targets == SUPPORTED_TARGETS,
        "supply_chain.cargo_deny.assets target set differs",
    )
    return CargoDenyPolicy(
        version=version,
        advisory_db=advisory_db,
        assets=tuple(sorted(assets, key=lambda asset: asset.target)),
    )


def verify_repository_bindings(root: Path, policy: CargoDenyPolicy) -> None:
    """Require the reviewed direct boundary and prohibit the retired Action."""

    verifier_label = "tools/verify-ci-pins.py"
    verifier_path = root / verifier_label
    _bounded_regular_bytes(verifier_path, MAX_WORKFLOW_BYTES, verifier_label)
    try:
        verifier = runpy.run_path(str(verifier_path))
    except (KeyError, OSError, SyntaxError, TypeError, ValueError) as error:
        raise PinPolicyError(
            "cannot structurally inspect protected CI Action uses"
        ) from error
    for workflow_label in (
        ".github/workflows/ci.yml",
        ".github/workflows/formal.yml",
    ):
        workflow = _decode_utf8(
            _bounded_regular_bytes(
                root / workflow_label,
                MAX_WORKFLOW_BYTES,
                workflow_label,
            ),
            workflow_label,
        )
        try:
            uses, problems = verifier["collect_uses"](
                workflow,
                label=workflow_label,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PinPolicyError(
                "cannot structurally inspect protected CI Action uses"
            ) from error
        require(
            problems == [],
            f"{workflow_label} is outside the admitted uses-safe YAML subset",
        )
        matches = [
            (use.kind, use.name, use.pin)
            for use in uses
            if use.kind == "action"
            and "/".join(use.name.split("/", maxsplit=2)[:2]).casefold()
            == FORBIDDEN_ACTION_REPOSITORY.casefold()
        ]
        require(
            matches == [],
            f"{workflow_label} must not execute the cargo-deny GitHub Action",
        )
        if workflow_label == ".github/workflows/ci.yml":
            try:
                supply_problems = verifier["verify_supply_chain_job"](
                    workflow,
                    label=workflow_label,
                )
            except (KeyError, TypeError, ValueError) as error:
                raise PinPolicyError(
                    "cannot verify the direct cargo-deny execution boundary"
                ) from error
            require(
                supply_problems == [],
                "the direct cargo-deny execution boundary differs",
            )
            linux_asset = next(
                asset
                for asset in policy.assets
                if asset.target == "x86_64-unknown-linux-musl"
            )
            require(
                workflow.count(linux_asset.url) == 1,
                "the Linux cargo-deny asset URL differs",
            )
            require(
                workflow.count(policy.advisory_db.archive_url) == 1,
                "the RustSec snapshot URL differs",
            )


def verify_snapshot_fresh(
    snapshot: RustSecSnapshot,
    *,
    now: dt.datetime | None = None,
) -> None:
    """Reject future and at-least-90-day-old advisory snapshots."""

    observed_now = now or dt.datetime.now(dt.timezone.utc)
    require(
        observed_now.tzinfo is not None and observed_now.utcoffset() is not None,
        "snapshot freshness clock must be offset-aware",
    )
    committed_at = _parse_committed_at(snapshot.committed_at)
    age = observed_now.astimezone(dt.timezone.utc) - committed_at.astimezone(
        dt.timezone.utc
    )
    maximum = dt.timedelta(days=snapshot.maximum_staleness_days)
    require(
        dt.timedelta(0) <= age < maximum,
        "RustSec advisory snapshot is future-dated or at least 90 days stale",
    )


def verify_repository_policy(
    root: Path,
    pins: Mapping[str, Any] | None = None,
    *,
    now: dt.datetime | None = None,
) -> CargoDenyPolicy:
    """Validate the closed schema, freshness, and workflow boundary."""

    policy = parse_policy(read_pins(root) if pins is None else pins)
    verify_snapshot_fresh(policy.advisory_db, now=now)
    verify_repository_bindings(root, policy)
    return policy


def _verified_file_bytes(
    path: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
    maximum_bytes: int,
    label: str,
) -> bytes:
    require(
        0 < expected_bytes <= maximum_bytes,
        f"{label} expected size violates the hard bound",
    )
    payload = _bounded_regular_bytes(path, maximum_bytes, label)
    require(len(payload) == expected_bytes, f"{label} byte size differs from pin")
    digest = hashlib.sha256(payload).hexdigest()
    require(
        hmac.compare_digest(digest, expected_sha256),
        f"{label} SHA-256 differs from pin",
    )
    return payload


def _gunzip_bounded(payload: bytes, *, maximum: int, label: str) -> bytes:
    """Decompress exactly one complete gzip member under a hard output cap."""

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        result = decompressor.decompress(payload, maximum + 1)
        require(
            len(result) <= maximum and not decompressor.unconsumed_tail,
            f"{label} exceeds the decompressed-byte bound",
        )
        remaining = maximum + 1 - len(result)
        result += decompressor.flush(remaining)
    except zlib.error as error:
        raise PinPolicyError(f"{label} is not a complete gzip stream") from error
    require(
        len(result) <= maximum,
        f"{label} exceeds the decompressed-byte bound",
    )
    require(decompressor.eof, f"{label} gzip stream is truncated")
    require(
        decompressor.unused_data == b"",
        f"{label} has trailing or concatenated gzip data",
    )
    return result


def _normalized_member_name(
    name: str,
    *,
    label: str = "cargo-deny archive",
) -> str:
    try:
        encoded_name = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PinPolicyError(f"{label} member name is not valid UTF-8") from error
    require(
        "\0" not in name
        and "\\" not in name
        and 0 < len(encoded_name) <= MAX_MEMBER_NAME_BYTES,
        f"{label} member name is invalid",
    )
    path = PurePosixPath(name)
    require(
        not path.is_absolute()
        and "." not in path.parts
        and ".." not in path.parts
        and path.as_posix() == name,
        f"{label} member path is not normalized: {name!r}",
    )
    return name


def extract_verified_binary(archive_path: Path, asset: CargoDenyAsset) -> bytes:
    """Return the verified binary from one closed, bounded release archive."""

    compressed = _verified_file_bytes(
        archive_path,
        expected_bytes=asset.archive_bytes,
        expected_sha256=asset.archive_sha256,
        maximum_bytes=MAX_ARCHIVE_BYTES,
        label="cargo-deny archive",
    )
    tar_payload = _gunzip_bounded(
        compressed,
        maximum=MAX_TAR_BYTES,
        label="cargo-deny archive",
    )
    # The version is intentionally derived from the canonical URL, never from
    # an archive-controlled path.
    filename = asset.url.rsplit("/", maxsplit=1)[1]
    archive_suffix = f"-{asset.target}.tar.gz"
    require(
        filename.startswith("cargo-deny-") and filename.endswith(archive_suffix),
        "cargo-deny asset URL does not encode the target",
    )
    version = filename[len("cargo-deny-") : -len(archive_suffix)]
    require(
        EXACT_VERSION.fullmatch(version) is not None
        and asset.target in SUPPORTED_TARGETS
        and asset.url
        == (
            "https://github.com/EmbarkStudios/cargo-deny/releases/download/"
            f"{version}/cargo-deny-{version}-{asset.target}.tar.gz"
        ),
        "cargo-deny asset identity is not canonical",
    )
    root = f"cargo-deny-{version}-{asset.target}"
    binary_name = f"{root}/cargo-deny"
    expected_names = {
        root,
        binary_name,
        *(f"{root}/{name}" for name in ANCILLARY_FILES),
    }
    seen: set[str] = set()
    binary: bytes | None = None
    total_regular_bytes = 0
    expected_offset = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as archive:
            for index, member in enumerate(archive):
                require(
                    index < MAX_ARCHIVE_MEMBERS,
                    "cargo-deny archive has too many members",
                )
                name = _normalized_member_name(member.name)
                require(
                    name not in seen, f"duplicate cargo-deny archive member {name!r}"
                )
                seen.add(name)
                require(
                    member.offset == expected_offset
                    and member.offset_data == member.offset + tarfile.BLOCKSIZE,
                    "cargo-deny archive uses non-canonical extension headers or gaps",
                )
                require(
                    not member.pax_headers,
                    "cargo-deny archive member has unreviewed PAX metadata",
                )
                if name == root:
                    require(
                        member.type == tarfile.DIRTYPE
                        and member.size == 0
                        and member.mode & 0o7777 == 0o755,
                        "cargo-deny archive root entry is not canonical",
                    )
                else:
                    expected_mode = (
                        0o755
                        if name == binary_name
                        else ANCILLARY_FILES.get(name.removeprefix(f"{root}/"))
                    )
                    require(
                        expected_mode is not None
                        and member.type == tarfile.REGTYPE
                        and member.mode & 0o7777 == expected_mode
                        and type(member.size) is int
                        and member.size >= 0,
                        f"cargo-deny archive member is not admitted: {name!r}",
                    )
                    if name == binary_name:
                        require(
                            member.size == asset.binary_bytes,
                            "cargo-deny binary byte size differs",
                        )
                    total_regular_bytes += member.size
                    require(
                        total_regular_bytes <= MAX_TAR_BYTES,
                        "cargo-deny archive declared payload exceeds the bound",
                    )
                    source = archive.extractfile(member)
                    require(source is not None, f"cannot read archive member {name!r}")
                    with source:
                        member_payload = source.read(member.size + 1)
                    require(
                        len(member_payload) == member.size,
                        f"cargo-deny archive member is truncated: {name!r}",
                    )
                    if name == binary_name:
                        binary = member_payload
                expected_offset = member.offset_data + (
                    (member.size + tarfile.BLOCKSIZE - 1)
                    // tarfile.BLOCKSIZE
                    * tarfile.BLOCKSIZE
                )
    except (tarfile.TarError, EOFError, OSError) as error:
        raise PinPolicyError("cargo-deny archive is not a complete tar file") from error

    require(seen == expected_names, "cargo-deny archive member set differs")
    require(len(seen) == MAX_ARCHIVE_MEMBERS, "cargo-deny archive member count differs")
    trailer = tar_payload[expected_offset:]
    require(
        len(trailer) >= 2 * tarfile.BLOCKSIZE and not any(trailer),
        "cargo-deny tar end marker is missing or has trailing data",
    )
    require(binary is not None, "cargo-deny binary is missing from archive")
    require(len(binary) == asset.binary_bytes, "cargo-deny binary byte size differs")
    digest = hashlib.sha256(binary).hexdigest()
    require(
        hmac.compare_digest(digest, asset.binary_sha256),
        "cargo-deny binary SHA-256 differs",
    )
    return binary


def verify_binary(
    binary_path: Path,
    asset: CargoDenyAsset,
    version: str,
) -> None:
    """Verify exact bytes, safe mode, and exact ``--version`` output."""

    _verified_file_bytes(
        binary_path,
        expected_bytes=asset.binary_bytes,
        expected_sha256=asset.binary_sha256,
        maximum_bytes=MAX_BINARY_BYTES,
        label="cargo-deny binary",
    )
    try:
        metadata = binary_path.lstat()
    except OSError as error:
        raise PinPolicyError("cannot inspect cargo-deny binary mode") from error
    require(
        metadata.st_mode & stat.S_IXUSR != 0 and metadata.st_mode & 0o022 == 0,
        "cargo-deny binary must be owner-executable and not group/world-writable",
    )
    try:
        completed = subprocess.run(
            (str(binary_path.absolute()), "--version"),
            cwd=binary_path.parent,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PinPolicyError("cannot execute the exact cargo-deny binary") from error
    require(
        len(completed.stdout) <= 1024 and len(completed.stderr) <= 1024,
        "cargo-deny --version output exceeds the bound",
    )
    require(
        completed.returncode == 0
        and completed.stdout == f"cargo-deny {version}\n".encode()
        and completed.stderr == b"",
        "cargo-deny binary did not report the exact pinned version",
    )


def _write_new_binary(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    require(no_follow is not None, "this platform lacks O_NOFOLLOW")
    try:
        descriptor = os.open(path, flags | no_follow, 0o700)
    except OSError as error:
        raise PinPolicyError("cannot create cargo-deny binary") from error
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "cannot complete cargo-deny binary write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    else:
        os.close(descriptor)


def install_verified_archive(
    archive_path: Path,
    destination: Path,
    asset: CargoDenyAsset,
    version: str,
) -> Path:
    """Install into one newly created directory, cleaning partial output."""

    binary = extract_verified_binary(archive_path, asset)
    try:
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as error:
        raise PinPolicyError(
            "cargo-deny destination must be a new directory"
        ) from error
    binary_path = destination / "cargo-deny"
    try:
        _write_new_binary(binary_path, binary)
        verify_binary(binary_path, asset, version)
    except BaseException:
        try:
            binary_path.unlink(missing_ok=True)
            destination.rmdir()
        except OSError as cleanup_error:
            raise PinPolicyError(
                "cargo-deny installation failed and cleanup was incomplete"
            ) from cleanup_error
        raise
    return binary_path


def _write_new_regular(path: Path, payload: bytes) -> None:
    """Create one owner-only regular file without following a final symlink."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    require(no_follow is not None, "this platform lacks O_NOFOLLOW")
    try:
        descriptor = os.open(path, flags | no_follow, 0o600)
    except OSError as error:
        raise PinPolicyError("cannot create RustSec advisory file") from error
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "cannot complete RustSec advisory file write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    else:
        os.close(descriptor)


def _extract_advisory_tree(
    tar_payload: bytes,
    destination: Path,
    snapshot: RustSecSnapshot,
) -> None:
    """Safely materialize the exact bounded snapshot beneath ``destination``."""

    archive_root = f"advisory-db-{snapshot.commit}"
    seen: set[str] = set()
    regular_files = 0
    directories = 0
    worktree_bytes = 0
    expected_end = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as archive:
            for index, member in enumerate(archive):
                require(
                    index < MAX_ADVISORY_MEMBERS,
                    "RustSec snapshot has too many members",
                )
                name = _normalized_member_name(
                    member.name,
                    label="RustSec snapshot",
                )
                require(name not in seen, f"duplicate RustSec snapshot member {name!r}")
                seen.add(name)
                path = PurePosixPath(name)
                require(
                    len(path.parts) > 0
                    and path.parts[0] == archive_root
                    and len(path.parts) <= 8,
                    f"RustSec snapshot member is outside the exact root: {name!r}",
                )
                require(
                    all(part.casefold() != ".git" for part in path.parts[1:]),
                    f"RustSec snapshot member enters reserved .git state: {name!r}",
                )
                require(
                    member.pax_headers == {"comment": snapshot.commit},
                    f"RustSec snapshot member has unreviewed PAX metadata: {name!r}",
                )
                relative = path.parts[1:]
                if not relative:
                    require(
                        index == 0
                        and member.type == tarfile.DIRTYPE
                        and member.size == 0
                        and member.mode & 0o7777 == 0o775,
                        "RustSec snapshot root entry is not canonical",
                    )
                    directories += 1
                    expected_end = member.offset_data
                    continue

                parent_name = PurePosixPath(*path.parts[:-1]).as_posix()
                require(
                    parent_name in seen,
                    f"RustSec snapshot parent appears after child: {name!r}",
                )
                target = destination.joinpath(*relative)
                try:
                    parent_metadata = target.parent.lstat()
                except OSError as error:
                    raise PinPolicyError(
                        f"RustSec snapshot parent is missing: {name!r}"
                    ) from error
                require(
                    stat.S_ISDIR(parent_metadata.st_mode),
                    f"RustSec snapshot parent is not a directory: {name!r}",
                )
                if member.type == tarfile.DIRTYPE:
                    require(
                        member.size == 0 and member.mode & 0o7777 == 0o775,
                        f"RustSec snapshot directory is not canonical: {name!r}",
                    )
                    try:
                        target.mkdir(mode=0o700, parents=False, exist_ok=False)
                    except OSError as error:
                        raise PinPolicyError(
                            f"cannot create RustSec snapshot directory: {name!r}"
                        ) from error
                    directories += 1
                else:
                    require(
                        member.type == tarfile.REGTYPE
                        and member.mode & 0o7777 == 0o664
                        and type(member.size) is int
                        and 0 < member.size <= MAX_ADVISORY_MEMBER_BYTES,
                        f"RustSec snapshot member is not an admitted file: {name!r}",
                    )
                    worktree_bytes += member.size
                    require(
                        worktree_bytes <= MAX_ADVISORY_WORKTREE_BYTES,
                        "RustSec snapshot declared payload exceeds the bound",
                    )
                    source = archive.extractfile(member)
                    if source is None:
                        raise PinPolicyError(f"cannot read RustSec member {name!r}")
                    with source:
                        payload = source.read(member.size + 1)
                    require(
                        len(payload) == member.size,
                        f"RustSec snapshot member is truncated: {name!r}",
                    )
                    _write_new_regular(target, payload)
                    regular_files += 1
                expected_end = member.offset_data + (
                    (member.size + tarfile.BLOCKSIZE - 1)
                    // tarfile.BLOCKSIZE
                    * tarfile.BLOCKSIZE
                )
    except (tarfile.TarError, EOFError, OSError) as error:
        raise PinPolicyError("RustSec snapshot is not a complete tar file") from error

    require(
        len(seen) == snapshot.member_count
        and regular_files == snapshot.regular_file_count
        and directories == snapshot.directory_count,
        "RustSec snapshot member counts differ from the pin",
    )
    require(
        worktree_bytes == snapshot.worktree_bytes,
        "RustSec snapshot worktree byte size differs from the pin",
    )
    trailer = tar_payload[expected_end:]
    require(
        len(trailer) >= 2 * tarfile.BLOCKSIZE and not any(trailer),
        "RustSec snapshot tar end marker is missing or has trailing data",
    )


def _validate_git_executable(git_executable: Path) -> None:
    """Reject PATH lookup, symlinks, and writable Git executables."""

    require(git_executable.is_absolute(), "Git executable path must be absolute")
    try:
        metadata = git_executable.lstat()
    except OSError as error:
        raise PinPolicyError("cannot inspect the Git executable") from error
    require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_mode & stat.S_IXUSR != 0
        and metadata.st_mode & 0o022 == 0,
        "Git executable must be an owner-executable, non-writable regular file",
    )


def _run_git(
    git_executable: Path,
    repository: Path,
    arguments: Sequence[str],
    *,
    stdin: bytes | None = None,
) -> bytes:
    """Run one bounded, noninteractive Git operation in the seed repository."""

    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(repository.parent),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    command = (
        str(git_executable),
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        str(repository),
        *arguments,
    )
    try:
        completed = subprocess.run(
            command,
            cwd=repository.parent,
            env=environment,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PinPolicyError(
            "cannot execute deterministic Git seed operation"
        ) from error
    require(
        len(completed.stdout) <= MAX_GIT_OUTPUT_BYTES
        and len(completed.stderr) <= MAX_GIT_OUTPUT_BYTES,
        "deterministic Git seed output exceeds the bound",
    )
    require(
        completed.returncode == 0,
        "deterministic Git seed operation failed: "
        + _decode_utf8(completed.stderr, "Git stderr").strip(),
    )
    return completed.stdout


def _seed_exact_git_tree(
    destination: Path,
    snapshot: RustSecSnapshot,
    git_executable: Path,
) -> None:
    """Create and verify the deterministic Git repository cargo-deny requires."""

    _run_git(
        git_executable,
        destination,
        (
            "init",
            "--quiet",
            "--initial-branch=main",
            "--object-format=sha1",
            "--template=",
            ".",
        ),
    )
    _run_git(git_executable, destination, ("add", "--force", "--all", "--", "."))
    observed_tree = _decode_utf8(
        _run_git(git_executable, destination, ("write-tree",)),
        "git write-tree output",
    ).strip()
    require(
        hmac.compare_digest(observed_tree, snapshot.tree),
        "RustSec snapshot reconstructed Git tree differs from the pin",
    )
    commit_payload = _seed_commit_payload(
        commit=snapshot.commit,
        tree=snapshot.tree,
        committed_at=snapshot.committed_at,
    )
    observed_commit = _decode_utf8(
        _run_git(
            git_executable,
            destination,
            ("hash-object", "-t", "commit", "-w", "--stdin"),
            stdin=commit_payload,
        ),
        "git hash-object output",
    ).strip()
    require(
        hmac.compare_digest(observed_commit, snapshot.seed_commit),
        "RustSec deterministic seed commit differs from the pin",
    )
    _run_git(
        git_executable,
        destination,
        ("update-ref", "refs/heads/main", snapshot.seed_commit),
    )
    observed_head = _decode_utf8(
        _run_git(git_executable, destination, ("rev-parse", "HEAD")),
        "git rev-parse output",
    ).strip()
    observed_head_tree = _decode_utf8(
        _run_git(git_executable, destination, ("show", "-s", "--format=%T", "HEAD")),
        "git show output",
    ).strip()
    require(
        hmac.compare_digest(observed_head, snapshot.seed_commit)
        and hmac.compare_digest(observed_head_tree, snapshot.tree),
        "RustSec seeded Git HEAD identity differs from the pin",
    )
    status = _run_git(
        git_executable,
        destination,
        ("status", "--porcelain=v1", "--untracked-files=all"),
    )
    require(status == b"", "RustSec seeded Git worktree is not clean")
    _run_git(
        git_executable,
        destination,
        ("fsck", "--full", "--strict", "--no-dangling"),
    )


def seed_advisory_database(
    archive_path: Path,
    cargo_home: Path,
    snapshot: RustSecSnapshot,
    *,
    git_executable: Path = Path("/usr/bin/git"),
    now: dt.datetime | None = None,
) -> Path:
    """Verify and seed cargo-deny's canonical RustSec database directory."""

    validated_snapshot = _parse_advisory_snapshot(snapshot._asdict())
    require(
        validated_snapshot == snapshot,
        "RustSec snapshot descriptor is not canonical",
    )
    verify_snapshot_fresh(snapshot, now=now)
    _validate_git_executable(git_executable)
    require(cargo_home.is_absolute(), "cargo home path must be absolute")
    try:
        cargo_home_metadata = cargo_home.lstat()
    except OSError as error:
        raise PinPolicyError("cargo home must be an existing directory") from error
    require(
        stat.S_ISDIR(cargo_home_metadata.st_mode)
        and cargo_home_metadata.st_mode & 0o022 == 0,
        "cargo home must be a non-group/world-writable real directory",
    )
    compressed = _verified_file_bytes(
        archive_path,
        expected_bytes=snapshot.archive_bytes,
        expected_sha256=snapshot.archive_sha256,
        maximum_bytes=MAX_ADVISORY_ARCHIVE_BYTES,
        label="RustSec snapshot archive",
    )
    tar_payload = _gunzip_bounded(
        compressed,
        maximum=MAX_ADVISORY_TAR_BYTES,
        label="RustSec snapshot archive",
    )
    require(
        len(tar_payload) == snapshot.tar_bytes,
        "RustSec snapshot tar byte size differs from the pin",
    )
    require(
        hmac.compare_digest(
            hashlib.sha256(tar_payload).hexdigest(),
            snapshot.tar_sha256,
        ),
        "RustSec snapshot tar SHA-256 differs from the pin",
    )

    db_root = cargo_home / "advisory-dbs"
    destination = db_root / snapshot.database_directory
    try:
        db_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as error:
        raise PinPolicyError(
            "RustSec advisory database root must be a new directory"
        ) from error
    try:
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        _extract_advisory_tree(tar_payload, destination, snapshot)
        _seed_exact_git_tree(destination, snapshot, git_executable)
    except BaseException:
        try:
            shutil.rmtree(db_root)
        except OSError as cleanup_error:
            raise PinPolicyError(
                "RustSec seed failed and cleanup was incomplete"
            ) from cleanup_error
        raise
    return destination


def host_target() -> str:
    """Map the current supported host to an exact release target."""

    system = platform.system()
    machine = platform.machine().lower()
    if system == "Darwin" and machine in {"arm64", "aarch64"}:
        return "aarch64-apple-darwin"
    if system == "Linux" and machine in {"amd64", "x86_64"}:
        return "x86_64-unknown-linux-musl"
    raise PinPolicyError(f"unsupported cargo-deny host: {system}/{machine}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-policy")
    install = subparsers.add_parser("install")
    install.add_argument("--archive", required=True, type=Path)
    install.add_argument("--destination", required=True, type=Path)
    install.add_argument("--target", choices=sorted(SUPPORTED_TARGETS))
    seed = subparsers.add_parser("seed-advisory-db")
    seed.add_argument("--archive", required=True, type=Path)
    seed.add_argument("--cargo-home", required=True, type=Path)
    seed.add_argument("--git", type=Path, default=Path("/usr/bin/git"))
    return parser


def main(arguments: Sequence[str] | None = None) -> None:
    """Run policy verification, binary installation, or RustSec seeding."""

    options = _parser().parse_args(arguments)
    policy = verify_repository_policy(ROOT)
    if options.command == "verify-policy":
        print(
            "pinned-cargo-deny: OK "
            f"(cargo-deny {policy.version}; RustSec "
            f"{policy.advisory_db.commit}; {len(policy.assets)} exact assets)"
        )
        return
    if options.command == "seed-advisory-db":
        destination = seed_advisory_database(
            options.archive,
            options.cargo_home,
            policy.advisory_db,
            git_executable=options.git,
        )
        print(f"pinned-cargo-deny: seeded verified RustSec database at {destination}")
        return
    target = options.target or host_target()
    asset = policy.asset_for(target)
    binary = install_verified_archive(
        options.archive,
        options.destination,
        asset,
        policy.version,
    )
    print(f"pinned-cargo-deny: installed verified {target} binary at {binary}")


if __name__ == "__main__":
    try:
        main()
    except PinPolicyError as error:
        print(f"pinned-cargo-deny: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from None
