#!/usr/bin/env python3
"""Validate and install Haldir's exact cargo-deny release asset.

The repository verifier calls :func:`verify_repository_policy`, so the
protected ``Verify source pins`` CI step rejects schema, Action, signed-plan,
and release-asset drift. Installation is deliberately offline: callers fetch
an archive separately, then this module verifies its exact size and digest,
parses a closed bounded tar layout without ``extractall``, verifies the binary,
and executes that exact path for an exact version check.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
import platform
import re
import runpy
import stat
import subprocess
import sys
import tarfile
import tomllib
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple, NoReturn

ROOT = Path(__file__).resolve().parents[1]
PIN_SCHEMA_VERSION = 1
MAX_POLICY_BYTES = 64 * 1024
MAX_WORKFLOW_BYTES = 1024 * 1024
MAX_PLAN_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 8_000_000
MAX_TAR_BYTES = 12_000_000
MAX_BINARY_BYTES = 10_000_000
MAX_ARCHIVE_MEMBERS = 5
MAX_MEMBER_NAME_BYTES = 256
VERSION_TIMEOUT_SECONDS = 10
CHECKSUM = re.compile(r"[0-9a-f]{64}")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
EXACT_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
ACTION_REPOSITORY = "EmbarkStudios/cargo-deny-action"
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
        "action_repository",
        "action_version",
        "action_commit",
        "assets",
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


class CargoDenyPolicy(NamedTuple):
    """The closed cargo-deny policy parsed from ``tools/pins.toml``."""

    version: str
    action_repository: str
    action_version: str
    action_commit: str
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
    action_repository = cargo_deny["action_repository"]
    action_version = cargo_deny["action_version"]
    action_commit = cargo_deny["action_commit"]
    require(
        action_repository == ACTION_REPOSITORY,
        "supply_chain.cargo_deny.action_repository is not the admitted Action",
    )
    require(
        isinstance(action_version, str)
        and EXACT_VERSION.fullmatch(action_version) is not None,
        "supply_chain.cargo_deny.action_version must be exact",
    )
    require(
        isinstance(action_commit, str)
        and FULL_SHA.fullmatch(action_commit) is not None,
        "supply_chain.cargo_deny.action_commit must be a full SHA",
    )

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
        action_repository=action_repository,
        action_version=action_version,
        action_commit=action_commit,
        assets=tuple(sorted(assets, key=lambda asset: asset.target)),
    )


def _load_json_object(payload: bytes, label: str) -> dict[str, Any]:
    """Decode a JSON object while rejecting duplicate member names."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PinPolicyError(f"{label} contains duplicate key {key!r}")
            value[key] = item
        return value

    def reject_constant(token: str) -> NoReturn:
        raise PinPolicyError(f"{label} contains non-finite number {token}")

    try:
        value = json.loads(
            _decode_utf8(payload, label),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        raise PinPolicyError(f"{label} is invalid JSON: {error}") from error
    require(type(value) is dict, f"{label} must contain a JSON object")
    return value


def verify_repository_bindings(root: Path, policy: CargoDenyPolicy) -> None:
    """Bind pins to the protected workflow and signed epoch-15 plan."""

    workflow_label = ".github/workflows/ci.yml"
    workflow = _decode_utf8(
        _bounded_regular_bytes(
            root / workflow_label,
            MAX_WORKFLOW_BYTES,
            workflow_label,
        ),
        workflow_label,
    )
    verifier_label = "tools/verify-ci-pins.py"
    verifier_path = root / verifier_label
    _bounded_regular_bytes(verifier_path, MAX_WORKFLOW_BYTES, verifier_label)
    try:
        verifier = runpy.run_path(str(verifier_path))
        uses, problems = verifier["collect_uses"](
            workflow,
            label=workflow_label,
        )
    except (KeyError, OSError, SyntaxError, TypeError, ValueError) as error:
        raise PinPolicyError(
            "cannot structurally inspect protected CI Action uses"
        ) from error
    require(
        problems == [],
        "protected CI is outside the admitted uses-safe YAML subset",
    )
    matches = [
        (use.kind, use.name, use.pin)
        for use in uses
        if use.kind == "action" and use.name == policy.action_repository
    ]
    require(
        matches == [("action", policy.action_repository, policy.action_commit)],
        "protected CI cargo-deny Action differs from tools/pins.toml",
    )
    annotated_line = (
        f"        uses: {policy.action_repository}@{policy.action_commit} "
        f"# v{policy.action_version}"
    )
    require(
        workflow.splitlines().count(annotated_line) == 1,
        "protected CI cargo-deny Action annotation differs from tools/pins.toml",
    )

    plan_label = (
        "release/0.9.0/current-head/closures/framework-recovery/FR-0014-plan.json"
    )
    plan = _load_json_object(
        _bounded_regular_bytes(root / plan_label, MAX_PLAN_BYTES, plan_label),
        plan_label,
    )
    correction = plan.get("correction")
    require(type(correction) is dict, "FR-0014 correction record is malformed")
    refresh = correction.get("ecosystem_pin_refresh")
    require(type(refresh) is dict, "FR-0014 ecosystem pin refresh is malformed")
    actions = refresh.get("actions", [])
    require(isinstance(actions, list), "FR-0014 ecosystem Action pins are malformed")
    matches = [
        action
        for action in actions
        if isinstance(action, dict) and action.get("name") == policy.action_repository
    ]
    expected = {
        "cargo_deny_version": policy.version,
        "commit": policy.action_commit,
        "name": policy.action_repository,
        "version": f"v{policy.action_version}",
    }
    require(
        matches == [expected],
        "signed FR-0014 cargo-deny identity differs from tools/pins.toml",
    )


def verify_repository_policy(
    root: Path,
    pins: Mapping[str, Any] | None = None,
) -> CargoDenyPolicy:
    """Validate the closed schema and both repository identity bindings."""

    policy = parse_policy(read_pins(root) if pins is None else pins)
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


def _gunzip_bounded(payload: bytes) -> bytes:
    """Decompress exactly one complete gzip member under a hard output cap."""

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        result = decompressor.decompress(payload, MAX_TAR_BYTES + 1)
        require(
            len(result) <= MAX_TAR_BYTES and not decompressor.unconsumed_tail,
            "cargo-deny archive exceeds the decompressed-byte bound",
        )
        remaining = MAX_TAR_BYTES + 1 - len(result)
        result += decompressor.flush(remaining)
    except zlib.error as error:
        raise PinPolicyError(
            "cargo-deny archive is not a complete gzip stream"
        ) from error
    require(
        len(result) <= MAX_TAR_BYTES,
        "cargo-deny archive exceeds the decompressed-byte bound",
    )
    require(decompressor.eof, "cargo-deny gzip stream is truncated")
    require(
        decompressor.unused_data == b"",
        "cargo-deny archive has trailing or concatenated gzip data",
    )
    return result


def _normalized_member_name(name: str) -> str:
    try:
        encoded_name = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PinPolicyError(
            "cargo-deny archive member name is not valid UTF-8"
        ) from error
    require(
        "\0" not in name
        and "\\" not in name
        and 0 < len(encoded_name) <= MAX_MEMBER_NAME_BYTES,
        "cargo-deny archive member name is invalid",
    )
    path = PurePosixPath(name)
    require(
        not path.is_absolute()
        and "." not in path.parts
        and ".." not in path.parts
        and path.as_posix() == name,
        f"cargo-deny archive member path is not normalized: {name!r}",
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
    tar_payload = _gunzip_bounded(compressed)
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
    return parser


def main(arguments: Sequence[str] | None = None) -> None:
    """Run offline policy verification or verified installation."""

    options = _parser().parse_args(arguments)
    policy = verify_repository_policy(ROOT)
    if options.command == "verify-policy":
        print(
            "pinned-cargo-deny: OK "
            f"(Action v{policy.action_version}; cargo-deny {policy.version}; "
            f"{len(policy.assets)} exact assets)"
        )
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
