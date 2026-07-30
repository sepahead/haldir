"""Adversarial tests for the exact cargo-deny pin and archive boundary."""

from __future__ import annotations

import copy
import contextlib
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import runpy
import shutil
import subprocess
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
SNAPSHOT_COMMIT = "1" * 40
SNAPSHOT_TREE = "2590718dd483f03cf0186695708d71aa685b1c92"
SNAPSHOT_SEED_COMMIT = "e32789151cc1da843f93b89e55f67ed859534f3b"
SNAPSHOT_COMMITTED_AT = "2026-07-29T08:17:10-07:00"
SNAPSHOT_ROOT = f"advisory-db-{SNAPSHOT_COMMIT}"
SNAPSHOT_README = b"fixture\n"
SNAPSHOT_ADVISORY = b'[advisory]\nid = "RUSTSEC-2099-0001"\n'


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


def advisory_members() -> list[tuple[tarfile.TarInfo, bytes]]:
    """Return a minimal canonical RustSec snapshot tree."""

    records: list[tuple[str, bytes | None]] = [
        (SNAPSHOT_ROOT, None),
        (f"{SNAPSHOT_ROOT}/crates", None),
        (f"{SNAPSHOT_ROOT}/crates/demo", None),
        (f"{SNAPSHOT_ROOT}/README.md", SNAPSHOT_README),
        (
            f"{SNAPSHOT_ROOT}/crates/demo/RUSTSEC-2099-0001.md",
            SNAPSHOT_ADVISORY,
        ),
    ]
    members: list[tuple[tarfile.TarInfo, bytes]] = []
    for name, payload in records:
        member = tarfile.TarInfo(name)
        member.mtime = 0
        member.uid = 0
        member.gid = 0
        member.pax_headers = {"comment": SNAPSHOT_COMMIT}
        if payload is None:
            member.type = tarfile.DIRTYPE
            member.mode = 0o775
            member.size = 0
            members.append((member, b""))
        else:
            member.type = tarfile.REGTYPE
            member.mode = 0o664
            member.size = len(payload)
            members.append((member, payload))
    return members


def advisory_tar_payload(
    members: list[tuple[tarfile.TarInfo, bytes]] | None = None,
) -> bytes:
    """Serialize one deterministic PAX snapshot fixture."""

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        selected = advisory_members() if members is None else members
        for member, payload in selected:
            archive.addfile(member, io.BytesIO(payload) if member.isreg() else None)
    return output.getvalue()


def snapshot_for(
    archive: bytes,
    tar: bytes,
    *,
    tree: str = SNAPSHOT_TREE,
    member_count: int = 5,
    regular_file_count: int = 2,
    directory_count: int = 3,
    worktree_bytes: int = len(SNAPSHOT_README) + len(SNAPSHOT_ADVISORY),
) -> object:
    """Build exact pins for one synthetic snapshot archive."""

    payload = POLICY._seed_commit_payload(
        commit=SNAPSHOT_COMMIT,
        tree=tree,
        committed_at=SNAPSHOT_COMMITTED_AT,
    )
    seed_commit = POLICY._git_object_id("commit", payload)
    return POLICY.RustSecSnapshot(
        repository_url=POLICY.RUSTSEC_REPOSITORY_URL,
        archive_url=(
            f"https://codeload.github.com/RustSec/advisory-db/tar.gz/{SNAPSHOT_COMMIT}"
        ),
        commit=SNAPSHOT_COMMIT,
        committed_at=SNAPSHOT_COMMITTED_AT,
        tree=tree,
        seed_commit=seed_commit,
        database_directory=POLICY.RUSTSEC_DATABASE_DIRECTORY,
        maximum_staleness_days=POLICY.RUSTSEC_MAXIMUM_STALENESS_DAYS,
        archive_bytes=len(archive),
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        tar_bytes=len(tar),
        tar_sha256=hashlib.sha256(tar).hexdigest(),
        member_count=member_count,
        regular_file_count=regular_file_count,
        directory_count=directory_count,
        worktree_bytes=worktree_bytes,
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
            policy.advisory_db.commit,
            "7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2",
        )
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

    def test_recorded_rustsec_snapshot_matches_independent_measurement(self) -> None:
        snapshot = POLICY.parse_policy(self.pins).advisory_db
        self.assertEqual(snapshot.repository_url, POLICY.RUSTSEC_REPOSITORY_URL)
        self.assertEqual(
            snapshot.archive_url,
            "https://codeload.github.com/RustSec/advisory-db/tar.gz/"
            "7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2",
        )
        self.assertEqual(snapshot.committed_at, "2026-07-29T08:17:10-07:00")
        self.assertEqual(
            snapshot.tree,
            "2d3ab21e05f8b06ad2e232f92894b5e247d817ce",
        )
        self.assertEqual(
            snapshot.seed_commit,
            "1ec5ce48144b04d9bf3e740b4dd3c2d61d8cc4ce",
        )
        self.assertEqual(snapshot.archive_bytes, 441_027)
        self.assertEqual(
            snapshot.archive_sha256,
            "ab968b67150079bc386d098311cdab98e23745d555b3018837c91f3ae847967a",
        )
        self.assertEqual(snapshot.tar_bytes, 2_652_160)
        self.assertEqual(
            snapshot.tar_sha256,
            "69306513f06cac8750f3e8dd17ce1a5eebce958b3ed9511ab7a3939b15555471",
        )
        self.assertEqual(
            (
                snapshot.member_count,
                snapshot.regular_file_count,
                snapshot.directory_count,
                snapshot.worktree_bytes,
            ),
            (2_083, 1_192, 891, 1_283_107),
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
        advisory_db = copy.deepcopy(self.pins)
        advisory_db["supply_chain"]["cargo_deny"]["advisory_db"]["unknown"] = "value"
        mutations.append(advisory_db)
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
            ".github/workflows/formal.yml",
            "tools/verify-ci-pins.py",
        )
        for relative in relative_paths:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return temporary

    def test_retired_cargo_deny_action_is_rejected_in_each_workflow(self) -> None:
        policy = POLICY.parse_policy(self.pins)
        action_names = (
            "EmbarkStudios/cargo-deny-action",
            "embarkstudios/CARGO-DENY-ACTION",
            "EmbarkStudios/cargo-deny-action/subdirectory",
        )
        for workflow in ("ci.yml", "formal.yml"):
            for action_name in action_names:
                with self.subTest(workflow=workflow, action_name=action_name):
                    with self.binding_fixture() as directory:
                        root = Path(directory)
                        path = root / ".github/workflows" / workflow
                        action = (
                            f"      - uses: {action_name}@"
                            "3c6349835b2b7b196a839186cb8b78e02f7b5f25\n"
                        )
                        path.write_text(path.read_text() + action)
                        with self.assertRaisesRegex(
                            POLICY.PinPolicyError,
                            "must not execute",
                        ):
                            POLICY.verify_repository_bindings(root, policy)

    def test_commented_action_text_is_not_an_executable_use(self) -> None:
        policy = POLICY.parse_policy(self.pins)
        with self.binding_fixture() as directory:
            root = Path(directory)
            path = root / ".github/workflows/ci.yml"
            comment = (
                "\n# uses: EmbarkStudios/cargo-deny-action@"
                "3c6349835b2b7b196a839186cb8b78e02f7b5f25\n"
            )
            path.write_text(path.read_text() + comment)
            POLICY.verify_repository_bindings(root, policy)

    def test_snapshot_freshness_is_strict_and_offset_aware(self) -> None:
        snapshot = POLICY.parse_policy(self.pins).advisory_db
        committed = dt.datetime.fromisoformat(snapshot.committed_at)
        POLICY.verify_snapshot_fresh(
            snapshot,
            now=committed + dt.timedelta(days=89, hours=23),
        )
        for now in (
            committed - dt.timedelta(microseconds=1),
            committed + dt.timedelta(days=90),
        ):
            with self.subTest(now=now):
                with self.assertRaisesRegex(
                    POLICY.PinPolicyError,
                    "future-dated|90 days stale",
                ):
                    POLICY.verify_snapshot_fresh(snapshot, now=now)
        with self.assertRaisesRegex(POLICY.PinPolicyError, "offset-aware"):
            POLICY.verify_snapshot_fresh(snapshot, now=dt.datetime(2026, 7, 30))

    def test_snapshot_seed_commit_and_directory_are_closed(self) -> None:
        mutations = (
            ("seed_commit", "0" * 40, "deterministic seed"),
            ("database_directory", "advisory-db-attacker", "canonical URL mapping"),
            ("maximum_staleness_days", 91, "must be 90"),
            ("committed_at", "2026-07-29T15:17:10Z", "not canonical"),
        )
        for field, replacement, diagnostic in mutations:
            with self.subTest(field=field):
                pins = copy.deepcopy(self.pins)
                pins["supply_chain"]["cargo_deny"]["advisory_db"][field] = replacement
                with self.assertRaisesRegex(POLICY.PinPolicyError, diagnostic):
                    POLICY.parse_policy(pins)


class RustSecSnapshotTests(unittest.TestCase):
    """Exercise exact snapshot extraction, freshness, and Git seeding."""

    @staticmethod
    def write_archive(root: Path, archive: bytes) -> Path:
        path = root / "advisory-db.tar.gz"
        path.write_bytes(archive)
        return path

    @staticmethod
    def fresh_now() -> dt.datetime:
        return dt.datetime.fromisoformat(SNAPSHOT_COMMITTED_AT) + dt.timedelta(days=1)

    def seed(
        self,
        root: Path,
        archive: bytes,
        tar: bytes,
        snapshot: object | None = None,
    ) -> tuple[Path, Path]:
        cargo_home = root / "cargo-home"
        cargo_home.mkdir(mode=0o700)
        archive_path = self.write_archive(root, archive)
        destination = POLICY.seed_advisory_database(
            archive_path,
            cargo_home,
            snapshot or snapshot_for(archive, tar),
            now=self.fresh_now(),
        )
        return cargo_home, destination

    def test_exact_snapshot_seeds_clean_deterministic_git_tree(self) -> None:
        tar = advisory_tar_payload()
        archive = compress_tar(tar)
        with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
            cargo_home, destination = self.seed(Path(directory), archive, tar)
            self.assertEqual(
                destination,
                cargo_home / "advisory-dbs" / POLICY.RUSTSEC_DATABASE_DIRECTORY,
            )
            self.assertEqual(
                (destination / "README.md").read_bytes(),
                SNAPSHOT_README,
            )
            self.assertEqual(
                (destination / "crates/demo/RUSTSEC-2099-0001.md").read_bytes(),
                SNAPSHOT_ADVISORY,
            )
            self.assertEqual(
                (destination / "README.md").stat().st_mode & 0o777,
                0o600,
            )
            self.assertEqual(
                (destination / "crates").stat().st_mode & 0o777,
                0o700,
            )
            head = (
                subprocess.run(
                    ("/usr/bin/git", "-C", str(destination), "rev-parse", "HEAD"),
                    check=True,
                    stdout=subprocess.PIPE,
                )
                .stdout.decode()
                .strip()
            )
            tree = (
                subprocess.run(
                    (
                        "/usr/bin/git",
                        "-C",
                        str(destination),
                        "show",
                        "-s",
                        "--format=%T",
                        "HEAD",
                    ),
                    check=True,
                    stdout=subprocess.PIPE,
                )
                .stdout.decode()
                .strip()
            )
            status = subprocess.run(
                (
                    "/usr/bin/git",
                    "-C",
                    str(destination),
                    "status",
                    "--porcelain=v1",
                ),
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
            self.assertEqual(head, SNAPSHOT_SEED_COMMIT)
            self.assertEqual(tree, SNAPSHOT_TREE)
            self.assertEqual(status, b"")

    def test_snapshot_archive_size_and_digest_are_exact(self) -> None:
        tar = advisory_tar_payload()
        archive = compress_tar(tar)
        descriptor = snapshot_for(archive, tar)
        mutations = (
            descriptor._replace(archive_bytes=len(archive) + 1),
            descriptor._replace(archive_sha256="0" * 64),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
                    root = Path(directory)
                    cargo_home = root / "cargo-home"
                    cargo_home.mkdir(mode=0o700)
                    path = self.write_archive(root, archive)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "byte size|SHA-256",
                    ):
                        POLICY.seed_advisory_database(
                            path,
                            cargo_home,
                            mutation,
                            now=self.fresh_now(),
                        )
                    self.assertFalse((cargo_home / "advisory-dbs").exists())

    def test_snapshot_tar_size_and_digest_are_exact(self) -> None:
        tar = advisory_tar_payload()
        archive = compress_tar(tar)
        descriptor = snapshot_for(archive, tar)
        mutations = (
            descriptor._replace(tar_bytes=len(tar) + 1),
            descriptor._replace(tar_sha256="0" * 64),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
                    root = Path(directory)
                    cargo_home = root / "cargo-home"
                    cargo_home.mkdir(mode=0o700)
                    path = self.write_archive(root, archive)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "tar byte size|tar SHA-256",
                    ):
                        POLICY.seed_advisory_database(
                            path,
                            cargo_home,
                            mutation,
                            now=self.fresh_now(),
                        )
                    self.assertFalse((cargo_home / "advisory-dbs").exists())

    def test_snapshot_rejects_escape_and_absolute_paths(self) -> None:
        for hostile_name in (
            f"{SNAPSHOT_ROOT}/../escape",
            "/tmp/escape",
        ):
            members = advisory_members()
            hostile = copy.copy(members[3][0])
            hostile.name = hostile_name
            members[3] = (hostile, members[3][1])
            tar = advisory_tar_payload(members)
            archive = compress_tar(tar)
            with self.subTest(name=hostile_name):
                with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
                    root = Path(directory)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "not normalized",
                    ):
                        self.seed(root, archive, tar)
                    self.assertFalse((root / "escape").exists())
                    self.assertFalse((root / "cargo-home/advisory-dbs").exists())

    def test_snapshot_rejects_links_and_special_files(self) -> None:
        for member_type in (
            tarfile.SYMTYPE,
            tarfile.LNKTYPE,
            tarfile.FIFOTYPE,
        ):
            members = advisory_members()
            hostile = copy.copy(members[3][0])
            hostile.type = member_type
            hostile.size = 0
            hostile.linkname = "../escape"
            members[3] = (hostile, b"")
            tar = advisory_tar_payload(members)
            archive = compress_tar(tar)
            with self.subTest(member_type=member_type):
                with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
                    root = Path(directory)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "not an admitted file",
                    ):
                        self.seed(root, archive, tar)
                    self.assertFalse((root / "cargo-home/advisory-dbs").exists())

    def test_snapshot_rejects_archive_controlled_git_state(self) -> None:
        for reserved in (".git", ".GIT"):
            members = advisory_members()
            hostile = copy.copy(members[3][0])
            hostile.name = f"{SNAPSHOT_ROOT}/{reserved}/config"
            members[3] = (hostile, members[3][1])
            tar = advisory_tar_payload(members)
            archive = compress_tar(tar)
            with self.subTest(reserved=reserved):
                with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
                    root = Path(directory)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "reserved .git state",
                    ):
                        self.seed(root, archive, tar)
                    self.assertFalse((root / "cargo-home/advisory-dbs").exists())

    def test_snapshot_rejects_duplicate_members(self) -> None:
        members = advisory_members()
        duplicate = copy.copy(members[3][0])
        members[4] = (duplicate, members[3][1])
        tar = advisory_tar_payload(members)
        archive = compress_tar(tar)
        with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
            root = Path(directory)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "duplicate"):
                self.seed(root, archive, tar)
            self.assertFalse((root / "cargo-home/advisory-dbs").exists())

    def test_snapshot_rejects_pax_and_mode_drift(self) -> None:
        mutations = []
        pax_members = advisory_members()
        pax_member = copy.copy(pax_members[3][0])
        pax_member.pax_headers = {"comment": "0" * 40}
        pax_members[3] = (pax_member, pax_members[3][1])
        mutations.append((pax_members, "PAX metadata"))
        mode_members = advisory_members()
        mode_member = copy.copy(mode_members[3][0])
        mode_member.mode = 0o755
        mode_members[3] = (mode_member, mode_members[3][1])
        mutations.append((mode_members, "not an admitted file"))
        for members, diagnostic in mutations:
            tar = advisory_tar_payload(members)
            archive = compress_tar(tar)
            with self.subTest(diagnostic=diagnostic):
                with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
                    root = Path(directory)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        diagnostic,
                    ):
                        self.seed(root, archive, tar)
                    self.assertFalse((root / "cargo-home/advisory-dbs").exists())

    def test_snapshot_count_and_payload_drift_are_rejected(self) -> None:
        tar = advisory_tar_payload()
        archive = compress_tar(tar)
        descriptor = snapshot_for(archive, tar)
        mutations = (
            descriptor._replace(member_count=6),
            descriptor._replace(regular_file_count=3),
            descriptor._replace(directory_count=4),
            descriptor._replace(worktree_bytes=descriptor.worktree_bytes + 1),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
                    root = Path(directory)
                    with self.assertRaisesRegex(
                        POLICY.PinPolicyError,
                        "member counts|worktree byte size",
                    ):
                        self.seed(root, archive, tar, mutation)
                    self.assertFalse((root / "cargo-home/advisory-dbs").exists())

    def test_snapshot_tree_mismatch_removes_partial_seed(self) -> None:
        tar = advisory_tar_payload()
        archive = compress_tar(tar)
        snapshot = snapshot_for(archive, tar, tree="0" * 40)
        with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
            root = Path(directory)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "Git tree differs"):
                self.seed(root, archive, tar, snapshot)
            self.assertFalse((root / "cargo-home/advisory-dbs").exists())

    def test_stale_snapshot_fails_before_creating_output(self) -> None:
        tar = advisory_tar_payload()
        archive = compress_tar(tar)
        snapshot = snapshot_for(archive, tar)
        with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
            root = Path(directory)
            cargo_home = root / "cargo-home"
            cargo_home.mkdir(mode=0o700)
            archive_path = self.write_archive(root, archive)
            stale_now = dt.datetime.fromisoformat(SNAPSHOT_COMMITTED_AT) + dt.timedelta(
                days=90
            )
            with self.assertRaisesRegex(POLICY.PinPolicyError, "90 days stale"):
                POLICY.seed_advisory_database(
                    archive_path,
                    cargo_home,
                    snapshot,
                    now=stale_now,
                )
            self.assertFalse((cargo_home / "advisory-dbs").exists())

    def test_existing_advisory_root_is_preserved(self) -> None:
        tar = advisory_tar_payload()
        archive = compress_tar(tar)
        snapshot = snapshot_for(archive, tar)
        with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
            root = Path(directory)
            cargo_home = root / "cargo-home"
            cargo_home.mkdir(mode=0o700)
            db_root = cargo_home / "advisory-dbs"
            db_root.mkdir(mode=0o700)
            marker = db_root / "owned"
            marker.write_text("preserve")
            archive_path = self.write_archive(root, archive)
            with self.assertRaisesRegex(
                POLICY.PinPolicyError,
                "root must be a new directory",
            ):
                POLICY.seed_advisory_database(
                    archive_path,
                    cargo_home,
                    snapshot,
                    now=self.fresh_now(),
                )
            self.assertEqual(marker.read_text(), "preserve")

    def test_symlink_cargo_home_is_rejected(self) -> None:
        tar = advisory_tar_payload()
        archive = compress_tar(tar)
        snapshot = snapshot_for(archive, tar)
        with tempfile.TemporaryDirectory(prefix="haldir-rustsec-") as directory:
            root = Path(directory)
            real_home = root / "real-cargo-home"
            real_home.mkdir(mode=0o700)
            cargo_home = root / "cargo-home"
            cargo_home.symlink_to(real_home, target_is_directory=True)
            archive_path = self.write_archive(root, archive)
            with self.assertRaisesRegex(POLICY.PinPolicyError, "real directory"):
                POLICY.seed_advisory_database(
                    archive_path,
                    cargo_home,
                    snapshot,
                    now=self.fresh_now(),
                )
            self.assertEqual(list(real_home.iterdir()), [])

    def test_cli_exposes_explicit_seed_command(self) -> None:
        options = POLICY._parser().parse_args(
            [
                "seed-advisory-db",
                "--archive",
                "snapshot.tar.gz",
                "--cargo-home",
                "/tmp/cargo-home",
                "--git",
                "/usr/bin/git",
            ]
        )
        self.assertEqual(options.command, "seed-advisory-db")
        self.assertEqual(options.archive, Path("snapshot.tar.gz"))
        self.assertEqual(options.cargo_home, Path("/tmp/cargo-home"))
        self.assertEqual(options.git, Path("/usr/bin/git"))


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
