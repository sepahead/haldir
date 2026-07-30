"""Adversarial tests for the exact cargo-deny pin and archive boundary."""

from __future__ import annotations

import copy
import contextlib
import gzip
import hashlib
import importlib.util
import io
import runpy
import shutil
import sys
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
TARGET = "aarch64-apple-darwin"
VERSION = "0.20.2"
ARCHIVE_ROOT = f"cargo-deny-{VERSION}-{TARGET}"
GOOD_BINARY = b"#!/bin/sh\nprintf 'cargo-deny 0.20.2\\n'\n"
BAD_VERSION_BINARY = b"#!/bin/sh\nprintf 'cargo-deny 0.20.1\\n'\n"


def load_module() -> ModuleType:
    """Load the sibling module under isolated Python execution."""

    path = ROOT / "tools" / "pinned_cargo_deny.py"
    spec = importlib.util.spec_from_file_location("haldir_pinned_cargo_deny", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


POLICY = load_module()


def regular(name: str, payload: bytes, mode: int = 0o644) -> tarfile.TarInfo:
    """Build one deterministic regular-file header."""

    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.mode = mode
    member.mtime = 0
    member.uid = 0
    member.gid = 0
    member.size = len(payload)
    return member


def canonical_members(
    binary: bytes = GOOD_BINARY,
) -> list[tuple[tarfile.TarInfo, bytes]]:
    """Return the five admitted release members."""

    root = tarfile.TarInfo(ARCHIVE_ROOT)
    root.type = tarfile.DIRTYPE
    root.mode = 0o755
    root.mtime = 0
    root.uid = 0
    root.gid = 0
    return [
        (root, b""),
        (regular(f"{ARCHIVE_ROOT}/README.md", b"readme\n"), b"readme\n"),
        (
            regular(f"{ARCHIVE_ROOT}/LICENSE-APACHE", b"apache\n"),
            b"apache\n",
        ),
        (regular(f"{ARCHIVE_ROOT}/cargo-deny", binary, 0o755), binary),
        (regular(f"{ARCHIVE_ROOT}/LICENSE-MIT", b"mit\n"), b"mit\n"),
    ]


def tar_payload(members: list[tuple[tarfile.TarInfo, bytes]]) -> bytes:
    """Serialize deterministic test members as an uncompressed tar."""

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for member, payload in members:
            archive.addfile(member, io.BytesIO(payload) if member.isreg() else None)
    return output.getvalue()


def compress_tar(payload: bytes) -> bytes:
    """Serialize one deterministic gzip member."""

    return gzip.compress(payload, mtime=0)


def asset_for(archive: bytes, binary: bytes = GOOD_BINARY):
    """Build an exact descriptor for one synthetic archive."""

    return POLICY.CargoDenyAsset(
        target=TARGET,
        url=(
            "https://github.com/EmbarkStudios/cargo-deny/releases/download/"
            f"{VERSION}/cargo-deny-{VERSION}-{TARGET}.tar.gz"
        ),
        archive_bytes=len(archive),
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        binary_bytes=len(binary),
        binary_sha256=hashlib.sha256(binary).hexdigest(),
    )


class CargoDenyPinTests(unittest.TestCase):
    """Exercise closed schema and repository identity bindings."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pins = tomllib.loads((ROOT / "tools" / "pins.toml").read_text())

    def test_repository_policy_passes(self) -> None:
        policy = POLICY.verify_repository_policy(ROOT, self.pins)
        self.assertEqual(policy.version, VERSION)
        self.assertEqual(
            {asset.target for asset in policy.assets},
            POLICY.SUPPORTED_TARGETS,
        )

    def test_existing_pin_verifier_enforces_closed_policy(self) -> None:
        verifier = runpy.run_path(str(ROOT / "tools" / "verify-pins.py"))
        pins = copy.deepcopy(self.pins)
        pins["supply_chain"]["cargo_deny"]["unknown"] = "rejected"
        diagnostics = io.StringIO()
        with contextlib.redirect_stderr(diagnostics):
            with self.assertRaises(SystemExit) as exit_status:
                verifier["verify_cargo_deny_policy"](pins)
        self.assertEqual(exit_status.exception.code, 1)
        self.assertIn("schema differs", diagnostics.getvalue())

    def test_recorded_macos_asset_matches_measured_release(self) -> None:
        policy = POLICY.parse_policy(self.pins)
        asset = policy.asset_for(TARGET)
        self.assertEqual(asset.archive_bytes, 4_517_865)
        self.assertEqual(
            asset.archive_sha256,
            "fe67d82a10d8597a3549364cb733a3f9cc1bfff9031b7ae46384a9f2a72090c3",
        )
        self.assertEqual(asset.binary_bytes, 7_456_248)
        self.assertEqual(
            asset.binary_sha256,
            "5f65c07c459c9514f0c97cc2e2fb6b120daef2d95aee31062cab4816cf027eb1",
        )

    def test_recorded_linux_asset_matches_measured_release(self) -> None:
        policy = POLICY.parse_policy(self.pins)
        asset = policy.asset_for("x86_64-unknown-linux-musl")
        self.assertEqual(asset.archive_bytes, 4_936_832)
        self.assertEqual(
            asset.archive_sha256,
            "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f",
        )
        self.assertEqual(asset.binary_bytes, 8_844_624)
        self.assertEqual(
            asset.binary_sha256,
            "b329e25933d01c36dd7c47d84ea5716694f9b7caf53a5003d45674703a8ed54a",
        )

    def test_unknown_schema_keys_are_rejected_at_every_level(self) -> None:
        mutations = []
        top_level = copy.deepcopy(self.pins)
        top_level["unknown"] = {}
        mutations.append(top_level)
        table = copy.deepcopy(self.pins)
        table["toolchain"]["unknown"] = "value"
        mutations.append(table)
        cargo_deny = copy.deepcopy(self.pins)
        cargo_deny["supply_chain"]["cargo_deny"]["unknown"] = "value"
        mutations.append(cargo_deny)
        asset = copy.deepcopy(self.pins)
        asset["supply_chain"]["cargo_deny"]["assets"][0]["unknown"] = "value"
        mutations.append(asset)
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaisesRegex(POLICY.PinPolicyError, "schema differs"):
                    POLICY.parse_policy(mutation)

    def test_missing_schema_key_is_rejected(self) -> None:
        pins = copy.deepcopy(self.pins)
        del pins["supply_chain"]["cargo_deny"]["assets"][0]["binary_sha256"]
        with self.assertRaisesRegex(POLICY.PinPolicyError, "schema differs"):
            POLICY.parse_policy(pins)

    def test_boolean_size_is_not_accepted_as_an_integer(self) -> None:
        pins = copy.deepcopy(self.pins)
        pins["supply_chain"]["cargo_deny"]["assets"][0]["archive_bytes"] = True
        with self.assertRaisesRegex(POLICY.PinPolicyError, "hard bound"):
            POLICY.parse_policy(pins)

    def test_asset_size_cannot_expand_the_hard_bound(self) -> None:
        pins = copy.deepcopy(self.pins)
        pins["supply_chain"]["cargo_deny"]["assets"][0]["archive_bytes"] = (
            POLICY.MAX_ARCHIVE_BYTES + 1
        )
        with self.assertRaisesRegex(POLICY.PinPolicyError, "hard bound"):
            POLICY.parse_policy(pins)

    def test_duplicate_target_is_rejected(self) -> None:
        pins = copy.deepcopy(self.pins)
        pins["supply_chain"]["cargo_deny"]["assets"][1]["target"] = TARGET
        with self.assertRaisesRegex(POLICY.PinPolicyError, "duplicate"):
            POLICY.parse_policy(pins)

    def test_dependency_values_and_direct_rustix_pin_are_closed(self) -> None:
        for replacement in ({"version": "1.1.4"}, "1.1.3"):
            pins = copy.deepcopy(self.pins)
            pins["dependencies"]["rustix"] = replacement
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(
                    POLICY.PinPolicyError,
                    "dependencies.rustix",
                ):
                    POLICY.parse_policy(pins)

    def binding_fixture(self) -> tempfile.TemporaryDirectory[str]:
        """Copy only the two repository-bound identity inputs."""

        temporary = tempfile.TemporaryDirectory(prefix="haldir-pin-binding-")
        root = Path(temporary.name)
        relative_paths = (
            ".github/workflows/ci.yml",
            "tools/verify-ci-pins.py",
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0014-plan.json"
            ),
        )
        for relative in relative_paths:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return temporary

    def test_protected_action_drift_is_rejected(self) -> None:
        policy = POLICY.parse_policy(self.pins)
        with self.binding_fixture() as directory:
            root = Path(directory)
            path = root / ".github/workflows/ci.yml"
            path.write_text(path.read_text().replace(policy.action_commit, "0" * 40, 1))
            with self.assertRaisesRegex(POLICY.PinPolicyError, "protected CI"):
                POLICY.verify_repository_bindings(root, policy)

    def test_commented_action_text_cannot_spoof_executable_binding(self) -> None:
        policy = POLICY.parse_policy(self.pins)
        with self.binding_fixture() as directory:
            root = Path(directory)
            path = root / ".github/workflows/ci.yml"
            exact = (
                f"        uses: {policy.action_repository}@{policy.action_commit} "
                f"# v{policy.action_version}"
            )
            drifted = (
                f"        uses: {policy.action_repository}@{'0' * 40} "
                f"# v{policy.action_version}"
            )
            text = path.read_text()
            self.assertEqual(text.count(exact), 1)
            path.write_text(text.replace(exact, drifted) + f"\n# {exact}\n")
            with self.assertRaisesRegex(POLICY.PinPolicyError, "protected CI"):
                POLICY.verify_repository_bindings(root, policy)

    def test_signed_plan_drift_is_rejected(self) -> None:
        policy = POLICY.parse_policy(self.pins)
        with self.binding_fixture() as directory:
            root = Path(directory)
            path = (
                root / "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0014-plan.json"
            )
            text = path.read_text()
            marker = '"cargo_deny_version": "0.20.2"'
            self.assertEqual(text.count(marker), 1)
            path.write_text(text.replace(marker, '"cargo_deny_version": "0.20.1"'))
            with self.assertRaisesRegex(POLICY.PinPolicyError, "signed FR-0014"):
                POLICY.verify_repository_bindings(root, policy)


class CargoDenyArchiveTests(unittest.TestCase):
    """Exercise archive and exact-binary validation against hostile shapes."""

    def write_archive(self, directory: Path, archive: bytes) -> Path:
        path = directory / "cargo-deny.tar.gz"
        path.write_bytes(archive)
        return path

    def test_exact_archive_is_parsed_without_path_extraction(self) -> None:
        archive = compress_tar(tar_payload(canonical_members()))
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), archive)
            self.assertEqual(
                POLICY.extract_verified_binary(path, asset_for(archive)),
                GOOD_BINARY,
            )

    def test_exact_archive_installs_and_executes_exact_version(self) -> None:
        archive = compress_tar(tar_payload(canonical_members()))
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            root = Path(directory)
            path = self.write_archive(root, archive)
            destination = root / "installed"
            binary = POLICY.install_verified_archive(
                path,
                destination,
                asset_for(archive),
                VERSION,
            )
            self.assertEqual(binary.read_bytes(), GOOD_BINARY)
            self.assertEqual(binary.stat().st_mode & 0o777, 0o700)

    def test_archive_size_and_digest_mismatch_are_rejected(self) -> None:
        archive = compress_tar(tar_payload(canonical_members()))
        descriptor = asset_for(archive)
        mutations = (
            descriptor._replace(archive_bytes=descriptor.archive_bytes + 1),
            descriptor._replace(archive_sha256="0" * 64),
        )
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), archive)
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "byte size|SHA-256",
                    ):
                        POLICY.extract_verified_binary(path, mutation)

    def test_absolute_and_parent_paths_are_rejected(self) -> None:
        for hostile_name in (
            "/tmp/escape",
            f"{ARCHIVE_ROOT}/../escape",
        ):
            members = canonical_members()
            payload = members[1][1]
            members[1] = (regular(hostile_name, payload), payload)
            archive = compress_tar(tar_payload(members))
            with self.subTest(name=hostile_name):
                with tempfile.TemporaryDirectory(
                    prefix="haldir-cargo-deny-"
                ) as directory:
                    root = Path(directory)
                    path = self.write_archive(root, archive)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "not normalized",
                    ):
                        POLICY.extract_verified_binary(path, asset_for(archive))
                    self.assertFalse((root / "escape").exists())

    def test_non_utf8_member_name_is_rejected_deterministically(self) -> None:
        with self.assertRaisesRegex(POLICY.PinPolicyError, "not valid UTF-8"):
            POLICY._normalized_member_name("invalid-\udcff")

    def test_alternate_regular_tar_types_are_rejected(self) -> None:
        for member_type in (
            tarfile.AREGTYPE,
            tarfile.CONTTYPE,
            tarfile.GNUTYPE_SPARSE,
        ):
            members = canonical_members()
            payload = members[1][1]
            hostile = regular(f"{ARCHIVE_ROOT}/README.md", payload)
            hostile.type = member_type
            members[1] = (hostile, payload)
            archive = compress_tar(tar_payload(members))
            with self.subTest(member_type=member_type):
                with tempfile.TemporaryDirectory(
                    prefix="haldir-cargo-deny-"
                ) as directory:
                    path = self.write_archive(Path(directory), archive)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "not admitted",
                    ):
                        POLICY.extract_verified_binary(path, asset_for(archive))

    def test_links_and_special_files_are_rejected(self) -> None:
        for member_type in (
            tarfile.SYMTYPE,
            tarfile.LNKTYPE,
            tarfile.FIFOTYPE,
        ):
            members = canonical_members()
            hostile = tarfile.TarInfo(f"{ARCHIVE_ROOT}/cargo-deny")
            hostile.type = member_type
            hostile.linkname = "../escape"
            hostile.mode = 0o755
            hostile.mtime = 0
            members[3] = (hostile, b"")
            archive = compress_tar(tar_payload(members))
            with self.subTest(member_type=member_type):
                with tempfile.TemporaryDirectory(
                    prefix="haldir-cargo-deny-"
                ) as directory:
                    path = self.write_archive(Path(directory), archive)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "not admitted",
                    ):
                        POLICY.extract_verified_binary(path, asset_for(archive))

    def test_duplicate_member_is_rejected(self) -> None:
        members = canonical_members()
        members[-1] = (
            regular(f"{ARCHIVE_ROOT}/cargo-deny", GOOD_BINARY, 0o755),
            GOOD_BINARY,
        )
        archive = compress_tar(tar_payload(members))
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), archive)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "duplicate"):
                POLICY.extract_verified_binary(path, asset_for(archive))

    def test_unexpected_member_is_rejected(self) -> None:
        members = canonical_members()
        members[-1] = (
            regular(f"{ARCHIVE_ROOT}/unexpected", b"unexpected"),
            b"unexpected",
        )
        archive = compress_tar(tar_payload(members))
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), archive)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "not admitted"):
                POLICY.extract_verified_binary(path, asset_for(archive))

    def test_truncated_gzip_is_rejected_even_when_descriptor_matches(self) -> None:
        archive = compress_tar(tar_payload(canonical_members()))[:-8]
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), archive)
            with self.assertRaisesRegex(
                POLICY.PinPolicyError,
                "gzip stream|truncated",
            ):
                POLICY.extract_verified_binary(path, asset_for(archive))

    def test_missing_tar_end_marker_is_rejected(self) -> None:
        payload = tar_payload(canonical_members())
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            end = max(
                member.offset_data
                + (member.size + tarfile.BLOCKSIZE - 1)
                // tarfile.BLOCKSIZE
                * tarfile.BLOCKSIZE
                for member in archive
            )
        compressed = compress_tar(payload[:end])
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), compressed)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "end marker"):
                POLICY.extract_verified_binary(path, asset_for(compressed))

    def test_concatenated_gzip_member_is_rejected(self) -> None:
        archive = compress_tar(tar_payload(canonical_members())) + gzip.compress(
            b"second member",
            mtime=0,
        )
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), archive)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "concatenated"):
                POLICY.extract_verified_binary(path, asset_for(archive))

    def test_decompression_bomb_is_rejected_at_the_hard_bound(self) -> None:
        archive = compress_tar(b"\0" * (POLICY.MAX_TAR_BYTES + 1))
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), archive)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "decompressed-byte"):
                POLICY.extract_verified_binary(path, asset_for(archive))

    def test_binary_size_and_digest_mismatch_are_rejected(self) -> None:
        archive = compress_tar(tar_payload(canonical_members()))
        descriptor = asset_for(archive)
        mutations = (
            descriptor._replace(binary_bytes=descriptor.binary_bytes + 1),
            descriptor._replace(binary_sha256="0" * 64),
        )
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            path = self.write_archive(Path(directory), archive)
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "binary byte size|binary SHA-256",
                    ):
                        POLICY.extract_verified_binary(path, mutation)

    def test_wrong_version_is_rejected_and_partial_install_is_removed(self) -> None:
        members = canonical_members(BAD_VERSION_BINARY)
        archive = compress_tar(tar_payload(members))
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            root = Path(directory)
            path = self.write_archive(root, archive)
            destination = root / "installed"
            with self.assertRaisesRegex(POLICY.PinPolicyError, "exact pinned version"):
                POLICY.install_verified_archive(
                    path,
                    destination,
                    asset_for(archive, BAD_VERSION_BINARY),
                    VERSION,
                )
            self.assertFalse(destination.exists())

    def test_symlink_archive_is_rejected(self) -> None:
        archive = compress_tar(tar_payload(canonical_members()))
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            root = Path(directory)
            real = self.write_archive(root, archive)
            link = root / "archive-link.tar.gz"
            link.symlink_to(real)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "regular file"):
                POLICY.extract_verified_binary(link, asset_for(archive))

    def test_existing_destination_is_not_overwritten(self) -> None:
        archive = compress_tar(tar_payload(canonical_members()))
        with tempfile.TemporaryDirectory(prefix="haldir-cargo-deny-") as directory:
            root = Path(directory)
            path = self.write_archive(root, archive)
            destination = root / "installed"
            destination.mkdir()
            marker = destination / "owned"
            marker.write_text("preserve")
            with self.assertRaisesRegex(POLICY.PinPolicyError, "new directory"):
                POLICY.install_verified_archive(
                    path,
                    destination,
                    asset_for(archive),
                    VERSION,
                )
            self.assertEqual(marker.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
