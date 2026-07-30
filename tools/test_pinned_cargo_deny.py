"""Adversarial tests for closed pins, workflows, and cargo-deny archives."""

from __future__ import annotations

import copy
import contextlib
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import runpy
import shlex
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


def load_ci_policy() -> ModuleType:
    """Load the CI pin verifier without executing its command-line entrypoint."""

    path = ROOT / "tools" / "verify-ci-pins.py"
    spec = importlib.util.spec_from_file_location("haldir_verify_ci_pins", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


POLICY = load_module()
CI_POLICY = load_ci_policy()


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
        formal = copy.deepcopy(self.pins)
        formal["formal"]["unknown"] = "value"
        mutations.append(formal)
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaisesRegex(POLICY.PinPolicyError, "schema differs"):
                    POLICY.parse_policy(mutation)

    def test_missing_schema_key_is_rejected(self) -> None:
        mutations = []
        missing_asset = copy.deepcopy(self.pins)
        del missing_asset["supply_chain"]["cargo_deny"]["assets"][0]["binary_sha256"]
        mutations.append(missing_asset)
        missing_formal = copy.deepcopy(self.pins)
        del missing_formal["formal"]["java_runtime_architecture"]
        mutations.append(missing_formal)
        for index, pins in enumerate(mutations):
            with self.subTest(mutation=index):
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

    def test_recorded_formal_runtime_and_asset_are_exact(self) -> None:
        self.assertEqual(self.pins["schema_version"], 3)
        self.assertEqual(len(self.pins["formal"]), 16)
        self.assertEqual(len(POLICY.EXACT_JAVA_PINS), 13)
        self.assertEqual(len(CI_POLICY.FORMAL_PIN_KEYS), 16)
        self.assertEqual(
            self.pins["formal"],
            {
                "tla_tools_version": "1.7.4",
                "tla_tools_bytes": 2_274_532,
                "tla_tools_sha256": (
                    "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
                ),
                **POLICY.EXACT_JAVA_PINS,
            },
        )

    def test_pin_schema_version_rejects_stale_and_unknown_values(self) -> None:
        for replacement in (1, 2, 4, True):
            with self.subTest(schema_version=replacement):
                pins = copy.deepcopy(self.pins)
                pins["schema_version"] = replacement
                with self.assertRaisesRegex(
                    POLICY.PinPolicyError,
                    "schema_version must be 3",
                ):
                    POLICY.parse_policy(pins)

    def test_formal_pin_types_and_platform_policy_are_closed(self) -> None:
        tla_mutations = (
            ("tla_tools_version", "latest", "exact release"),
            ("tla_tools_version", "01.7.4", "exact release"),
            ("tla_tools_bytes", True, "hard bound"),
            (
                "tla_tools_bytes",
                POLICY.MAX_FORMAL_ASSET_BYTES + 1,
                "hard bound",
            ),
            ("tla_tools_sha256", "0" * 63, "not exact"),
        )
        for field, replacement, diagnostic in tla_mutations:
            with self.subTest(field=field, replacement=replacement):
                pins = copy.deepcopy(self.pins)
                pins["formal"][field] = replacement
                with self.assertRaisesRegex(POLICY.PinPolicyError, diagnostic):
                    POLICY.parse_policy(pins)
        java_mutations = {
            "java_distribution": "zulu",
            "java_release_tag": "jdk-21.0.11+11",
            "java_archive_package": "jdk",
            "java_archive_architecture": "aarch64",
            "java_archive_name": "OpenJDK21U-jre_x64_linux_hotspot_latest.tar.gz",
            "java_archive_root": "jdk-21.0.11+10",
            "java_archive_url": (
                "http://github.com/adoptium/temurin21-binaries/releases/latest/"
                "OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz"
            ),
            "java_archive_bytes": True,
            "java_archive_sha256": "0" * 64,
            "java_runtime_vendor": "Oracle Corporation",
            "java_runtime_version": "21.0.11+11-LTS",
            "java_specification_version": "22",
            "java_runtime_architecture": "x86_64",
        }
        for field, replacement in java_mutations.items():
            with self.subTest(field=field, replacement=replacement):
                pins = copy.deepcopy(self.pins)
                pins["formal"][field] = replacement
                with self.assertRaises(POLICY.PinPolicyError) as raised:
                    POLICY.parse_policy(pins)
                self.assertIn(f"formal.{field}", str(raised.exception))

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


class WorkflowPinContractTests(unittest.TestCase):
    """Exercise PR isolation, main concurrency, and formal runtime bindings."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pins = tomllib.loads((ROOT / "tools" / "pins.toml").read_text())
        cls.ci = (ROOT / ".github/workflows/ci.yml").read_text()
        cls.formal = (ROOT / ".github/workflows/formal.yml").read_text()
        cls.formal_pins = CI_POLICY.parse_formal_pins(cls.pins)

    def test_repository_workflow_pin_verifier_passes(self) -> None:
        completed = subprocess.run(
            (sys.executable, "-I", "-B", "tools/verify-ci-pins.py"),
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("16 immutable Action uses", completed.stdout)
        self.assertIn("Java 21.0.11+10-LTS pinned", completed.stdout)

    def test_setup_java_is_retired_from_the_exact_action_baseline(self) -> None:
        self.assertEqual(sum(CI_POLICY.REQUIRED_ACTION_PINS.values()), 16)
        self.assertFalse(
            any(
                repository == "actions/setup-java"
                for repository, _digest in CI_POLICY.REQUIRED_ACTION_PINS
            )
        )
        self.assertNotIn("actions/setup-java@", self.formal)

    def test_workflow_envelopes_and_event_isolation_pass(self) -> None:
        for workflow, text in (("ci", self.ci), ("formal", self.formal)):
            with self.subTest(workflow=workflow):
                self.assertEqual(
                    CI_POLICY.verify_workflow_envelope(
                        text,
                        label=workflow,
                        workflow=workflow,
                    ),
                    [],
                )
                self.assertEqual(
                    CI_POLICY.verify_required_checks_run_on_pr(
                        text,
                        label=workflow,
                    ),
                    [],
                )
                self.assertEqual(
                    CI_POLICY.verify_python_isolation(
                        text,
                        label=workflow,
                    ),
                    [],
                )
                self.assertEqual(
                    CI_POLICY.verify_required_job_blocks(
                        text,
                        label=workflow,
                    ),
                    [],
                )
        self.assertEqual(
            CI_POLICY.verify_supply_chain_job(
                self.ci,
                label="ci",
            ),
            [],
        )
        self.assertEqual(
            CI_POLICY.verify_gh_cli_material(
                self.ci,
                label="ci",
            ),
            [],
        )
        self.assertEqual(
            CI_POLICY.verify_trusted_event_steps(
                self.ci,
                label="ci",
                job="supply-chain",
            ),
            [],
        )
        self.assertEqual(
            CI_POLICY.verify_pr_recovery_step(
                self.ci,
                label="ci",
            ),
            [],
        )
        self.assertEqual(
            CI_POLICY.verify_trusted_event_steps(
                self.formal,
                label="formal",
                job="tlc-model-check",
            ),
            [],
        )
        self.assertEqual(
            CI_POLICY.verify_formal_job(
                self.formal,
                label="formal",
                pins=self.formal_pins,
            ),
            [],
        )

    def test_github_cli_environment_interface_is_epoch_17(self) -> None:
        canonical = "HALDIR_FR0016_GH"
        mutations = (
            self.ci.replace(canonical, "HALDIR_FR0015_GH", 1),
            self.ci.replace(
                f"          printf '{canonical}=%s\\n'",
                "          printf 'HALDIR_FR0015_GH=%s\\n' \"$GH_BIN\""
                ' >> "$GITHUB_ENV"\n'
                f"          printf '{canonical}=%s\\n'",
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                problems = CI_POLICY.verify_gh_cli_material(
                    mutation,
                    label="ci",
                )
                self.assertTrue(
                    any(
                        "environment interface differs" in problem
                        for problem in problems
                    ),
                    problems,
                )

    def test_pr_recovery_step_has_exact_hermetic_commands(self) -> None:
        mutations = (
            self.ci.replace(
                "        if: github.event_name == 'pull_request'\n",
                "        if: github.event_name != 'pull_request'\n",
                1,
            ),
            self.ci.replace(
                "python3 -I -B -W error "
                "tools/release/test_verify_framework_recovery_fr_0016.py",
                "python3 -I -B tools/release/test_verify_framework_recovery_fr_0016.py",
                1,
            ),
            self.ci.replace(
                "          python3 -I -B -W error tools/test_pinned_cargo_deny.py\n",
                "",
                1,
            ),
            self.ci.replace(
                "          python3 -I -B -W error tools/test_run_formal.py\n",
                "",
                1,
            ),
            self.ci.replace(
                "          python3 -I -B -W error tools/test_run_formal.py\n",
                "          python3 -I -B -W error tools/test_run_formal.py\n"
                "          python3 -I -B tools/verify-ci-pins.py\n",
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                problems = CI_POLICY.verify_pr_recovery_step(
                    mutation,
                    label="ci",
                )
                self.assertTrue(problems)

    def test_workflow_python_entrypoints_require_exact_isolation(self) -> None:
        mutations = (
            self.ci.replace(
                "run: python3 -I -B tools/verify-pins.py",
                "run: python3 tools/verify-pins.py",
                1,
            ),
            self.ci.replace(
                "run: python3 -I -B tools/verify-pins.py",
                "run: /usr/bin/python3 -I -B tools/verify-pins.py",
                1,
            ),
            self.ci.replace(
                "run: python3 -I -B tools/verify-pins.py",
                "run: python3 -B tools/verify-pins.py",
                1,
            ),
            self.ci.replace(
                CI_POLICY.ISOLATED_SECURE_ZENOH_COMMAND,
                CI_POLICY.ISOLATED_SECURE_ZENOH_COMMAND.replace(
                    "verify-secure-zenoh.py",
                    "verify-claims.py",
                ),
                1,
            ),
            self.ci.replace(
                CI_POLICY.PR_RECOVERY_COMMANDS[2],
                CI_POLICY.PR_RECOVERY_COMMANDS[2].replace(
                    "test_run_formal.py",
                    "verify-claims.py",
                ),
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                problems = CI_POLICY.verify_python_isolation(
                    mutation,
                    label="ci",
                )
                self.assertTrue(
                    any("isolated command" in problem for problem in problems),
                    problems,
                )

    def test_isolated_python_blocks_sibling_stdlib_shadowing(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="haldir-python-isolation-",
        ) as directory:
            root = Path(directory)
            for relative in (
                ".github/workflows/ci.yml",
                ".github/workflows/formal.yml",
                "tools/pins.toml",
                "tools/verify-ci-pins.py",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            (root / "tools/hashlib.py").write_text("import os\nos._exit(0)\n")
            plain = subprocess.run(
                (sys.executable, "tools/verify-ci-pins.py"),
                cwd=root,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            isolated = subprocess.run(
                (sys.executable, "-I", "-B", "tools/verify-ci-pins.py"),
                cwd=root,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertEqual(plain.stdout, "")
        self.assertEqual(isolated.returncode, 0, isolated.stderr)
        self.assertIn("verify-ci-pins: OK", isolated.stdout)

    def test_whitelisted_sibling_launcher_preserves_stdlib_priority(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="haldir-sibling-launcher-",
        ) as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            for name in ("secure_zenoh.py", "verify-secure-zenoh.py"):
                shutil.copy2(ROOT / "tools" / name, tools / name)
            shutil.copytree(
                ROOT / "deploy" / "secure-reference-v1",
                root / "deploy" / "secure-reference-v1",
            )
            (tools / "hashlib.py").write_text("import os\nos._exit(0)\n")
            command = shlex.split(CI_POLICY.ISOLATED_SECURE_ZENOH_COMMAND)
            command[0] = sys.executable
            completed = subprocess.run(
                command,
                cwd=root,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("verify-secure-zenoh: OK", completed.stdout)

    def test_ci_result_identity_is_epoch_17_and_fr_0016(self) -> None:
        mutation = self.ci.replace(
            "framework_recovery_fr_0016_result.py",
            "framework_recovery_fr_0015_result.py",
            1,
        )
        problems = CI_POLICY.verify_supply_chain_job(
            mutation,
            label="ci",
        )
        self.assertTrue(
            any(
                "framework_recovery_fr_0016_result.py" in problem
                for problem in problems
            ),
            problems,
        )

    def test_main_runs_cannot_be_cancelled_or_coalesced(self) -> None:
        mutations = (
            self.ci.replace(
                "ci-${{ github.ref == 'refs/heads/main' && "
                "github.run_id || github.ref }}",
                "ci-${{ github.ref }}",
                1,
            ),
            self.ci.replace(
                "cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}",
                "cancel-in-progress: true",
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                problems = CI_POLICY.verify_workflow_envelope(
                    mutation,
                    label="ci",
                    workflow="ci",
                )
                self.assertTrue(
                    any("isolate every main run" in problem for problem in problems),
                    problems,
                )

    def test_workflow_event_and_concurrency_surfaces_are_closed(self) -> None:
        extra_event = self.formal.replace(
            "  workflow_dispatch:\n\nconcurrency:\n",
            "  workflow_dispatch:\n  pull_request_target:\n\nconcurrency:\n",
            1,
        )
        queued_main = self.formal.replace(
            "  cancel-in-progress: "
            "${{ github.ref != 'refs/heads/main' }}\n\n"
            "permissions:\n",
            "  cancel-in-progress: "
            "${{ github.ref != 'refs/heads/main' }}\n"
            "  queue: max\n\n"
            "permissions:\n",
            1,
        )
        expectations = (
            (extra_event, "every branch push"),
            (queued_main, "isolate every main run"),
            (
                self.formal + "\non:\n  workflow_dispatch:\n",
                "top-level 'on' key",
            ),
        )
        for mutation, diagnostic in expectations:
            with self.subTest(diagnostic=diagnostic):
                problems = CI_POLICY.verify_workflow_envelope(
                    mutation,
                    label="formal",
                    workflow="formal",
                )
                self.assertTrue(
                    any(diagnostic in problem for problem in problems),
                    problems,
                )

    def test_workflow_level_environment_and_shell_overrides_are_forbidden(self) -> None:
        environment = self.ci.replace(
            "\npermissions:\n",
            "\nenv:\n  BASH_ENV: tools/attacker.sh\n\npermissions:\n",
            1,
        )
        defaults = self.ci.replace(
            "\npermissions:\n",
            "\ndefaults:\n"
            "  run:\n"
            "    shell: /bin/bash --noprofile --norc {0}\n\n"
            "permissions:\n",
            1,
        )
        for name, mutation in (("environment", environment), ("defaults", defaults)):
            with self.subTest(mutation=name):
                _uses, syntax_problems = CI_POLICY.collect_uses(
                    mutation,
                    label="ci",
                )
                self.assertEqual(syntax_problems, [])
                problems = CI_POLICY.verify_workflow_envelope(
                    mutation,
                    label="ci",
                    workflow="ci",
                )
                self.assertTrue(
                    any(
                        "top-level key multiset differs" in problem
                        for problem in problems
                    ),
                    problems,
                )

    def test_pull_requests_cannot_bypass_the_merge_commit(self) -> None:
        mutation = self.formal.replace(
            "          fetch-depth: 0\n",
            "          fetch-depth: 0\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n",
            1,
        )
        problems = CI_POLICY.verify_workflow_envelope(
            mutation,
            label="formal",
            workflow="formal",
        )
        self.assertTrue(
            any("merge commit" in problem for problem in problems),
            problems,
        )
        self.assertTrue(
            any("head bypass" in problem for problem in problems),
            problems,
        )

    def test_required_job_hashes_reject_checkout_and_command_bypasses(self) -> None:
        foreign_checkout = self.ci.replace(
            "          persist-credentials: false\n",
            "          persist-credentials: false\n"
            "          repository: octocat/Hello-World\n",
            1,
        )
        continue_on_error = self.ci.replace(
            "      - name: Format check\n        run: cargo fmt --all -- --check\n",
            "      - name: Format check\n"
            "        continue-on-error: true\n"
            "        run: cargo fmt --all -- --check\n",
            1,
        )
        no_op = self.ci.replace(
            "        run: cargo fmt --all -- --check\n",
            '        run: "true"\n',
            1,
        )
        for name, mutation in (
            ("foreign-checkout", foreign_checkout),
            ("continue-on-error", continue_on_error),
            ("no-op", no_op),
        ):
            with self.subTest(mutation=name):
                _uses, syntax_problems = CI_POLICY.collect_uses(
                    mutation,
                    label="ci",
                )
                self.assertEqual(syntax_problems, [])
                problems = CI_POLICY.verify_required_job_blocks(
                    mutation,
                    label="ci",
                )
                self.assertIn(
                    "ci:build-test exact reviewed job block mismatch",
                    problems,
                )

    def test_required_check_job_names_are_closed(self) -> None:
        mutation = self.ci.replace("  build-test:\n", "  build-tests:\n", 1)
        problems = CI_POLICY.verify_workflow_envelope(
            mutation,
            label="ci",
            workflow="ci",
        )
        self.assertTrue(any("job set" in problem for problem in problems), problems)

    def test_required_build_steps_cannot_be_event_gated(self) -> None:
        mutation = self.ci.replace(
            "      - name: Format check\n",
            "      - name: Format check\n"
            "        if: github.event_name != 'pull_request'\n",
            1,
        )
        problems = CI_POLICY.verify_required_checks_run_on_pr(
            mutation,
            label="ci",
        )
        self.assertTrue(
            any("run every required step" in problem for problem in problems),
            problems,
        )

    def test_oidc_permission_cannot_escape_the_attester(self) -> None:
        mutation = self.ci.replace(
            "permissions:\n  contents: read\n",
            "permissions:\n  contents: read\n  id-token: write\n",
            1,
        )
        problems = CI_POLICY.verify_workflow_envelope(
            mutation,
            label="ci",
            workflow="ci",
        )
        self.assertTrue(
            any("isolated attester" in problem for problem in problems),
            problems,
        )

    def test_required_jobs_cannot_override_permissions_with_yaml_scalars(self) -> None:
        quoted_write = self.ci.replace(
            "  build-test:\n    runs-on: ubuntu-24.04\n",
            "  build-test:\n"
            "    permissions:\n"
            "      contents: read\n"
            "      id-token: 'write'\n"
            "    runs-on: ubuntu-24.04\n",
            1,
        )
        folded_write_all = self.ci.replace(
            "  build-test:\n    runs-on: ubuntu-24.04\n",
            "  build-test:\n"
            "    permissions: >-\n"
            "      write-all\n"
            "    runs-on: ubuntu-24.04\n",
            1,
        )
        for name, mutation in (
            ("quoted-write", quoted_write),
            ("folded-write-all", folded_write_all),
        ):
            with self.subTest(mutation=name):
                syntax_problems = CI_POLICY.validate_workflow_syntax(
                    mutation,
                    label="ci",
                )
                self.assertEqual(syntax_problems, [])
                problems = CI_POLICY.verify_workflow_envelope(
                    mutation,
                    label="ci",
                    workflow="ci",
                )
                self.assertTrue(
                    any(
                        "job-level permissions are forbidden" in problem
                        for problem in problems
                    ),
                    problems,
                )

    def test_only_named_history_bound_steps_are_pr_excluded(self) -> None:
        mutation = self.ci.replace(
            "        if: github.event_name != 'pull_request'\n",
            "        if: github.ref == 'refs/heads/main'\n",
            1,
        )
        problems = CI_POLICY.verify_trusted_event_steps(
            mutation,
            label="ci",
            job="supply-chain",
        )
        self.assertTrue(
            any("skipped only for pull requests" in problem for problem in problems),
            problems,
        )
        self.assertTrue(
            any("pull-request exclusions" in problem for problem in problems),
            problems,
        )

    def test_diagnostic_log_upload_remains_distinct_from_canonical_result(self) -> None:
        job = CI_POLICY._job_block(
            self.formal,
            "tlc-model-check",
            label="formal",
        )
        diagnostic = CI_POLICY._step_block(
            job,
            "Upload TLC log",
            label="formal:tlc-model-check",
        )
        canonical = CI_POLICY._step_block(
            job,
            "Upload canonical epoch-17 formal result",
            label="formal:tlc-model-check",
        )
        self.assertIn("        if: always()\n", diagnostic)
        self.assertNotIn("github.event_name != 'pull_request'", diagnostic)
        self.assertTrue(
            canonical.startswith(
                "      - name: Upload canonical epoch-17 formal result\n"
                "        if: github.event_name != 'pull_request'\n"
            )
        )

    def test_formal_pipeline_requires_pipefail_and_hardened_tls(self) -> None:
        no_pipefail = self.formal.replace(
            "      - name: Model-check HaldirAuthority\n"
            "        shell: /bin/bash --noprofile --norc -euo pipefail {0}\n",
            "      - name: Model-check HaldirAuthority\n"
            "        shell: /bin/bash --noprofile --norc -eu {0}\n",
            1,
        )
        problems = CI_POLICY.verify_formal_job(
            no_pipefail,
            label="formal",
            pins=self.formal_pins,
        )
        self.assertTrue(
            any("pipeline failures fatal" in problem for problem in problems),
            problems,
        )
        weak_tls = self.formal.replace("            --tlsv1.2 \\\n", "", 1)
        problems = CI_POLICY.verify_formal_job(
            weak_tls,
            label="formal",
            pins=self.formal_pins,
        )
        self.assertTrue(any("--tlsv1.2" in problem for problem in problems), problems)

    def test_formal_workflow_must_match_every_closed_pin(self) -> None:
        for field in self.formal_pins._fields:
            current = getattr(self.formal_pins, field)
            replacement = current + 1 if type(current) is int else f"{current}-mutated"
            with self.subTest(field=field):
                parsed = self.formal_pins._replace(**{field: replacement})
                problems = CI_POLICY.verify_formal_job(
                    self.formal,
                    label="formal",
                    pins=parsed,
                )
                self.assertTrue(
                    any(
                        "requires" in problem and str(replacement) in problem
                        for problem in problems
                    ),
                    problems,
                )

    def test_ci_formal_pin_parser_rejects_schema_and_type_ambiguity(self) -> None:
        mutations = []
        stale_schema = copy.deepcopy(self.pins)
        stale_schema["schema_version"] = 1
        mutations.append(stale_schema)
        previous_schema = copy.deepcopy(self.pins)
        previous_schema["schema_version"] = 2
        mutations.append(previous_schema)
        future_schema = copy.deepcopy(self.pins)
        future_schema["schema_version"] = 4
        mutations.append(future_schema)
        unknown = copy.deepcopy(self.pins)
        unknown["formal"]["unknown"] = "value"
        mutations.append(unknown)
        missing = copy.deepcopy(self.pins)
        del missing["formal"]["java_archive_package"]
        mutations.append(missing)
        boolean_size = copy.deepcopy(self.pins)
        boolean_size["formal"]["tla_tools_bytes"] = True
        mutations.append(boolean_size)
        boolean_archive_size = copy.deepcopy(self.pins)
        boolean_archive_size["formal"]["java_archive_bytes"] = True
        mutations.append(boolean_archive_size)
        for field, current in POLICY.EXACT_JAVA_PINS.items():
            wrong_java = copy.deepcopy(self.pins)
            wrong_java["formal"][field] = (
                current + 1 if type(current) is int else f"{current}-mutated"
            )
            mutations.append(wrong_java)
        for index, pins in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(ValueError):
                    CI_POLICY.parse_formal_pins(pins)

    def test_formal_archive_member_grammar_rejects_traversal_and_types(self) -> None:
        mutations = (
            (
                self.formal.replace(
                    '                [[ "$COMPONENT" != ".." ]]\n',
                    "",
                    1,
                ),
                '[[ "$COMPONENT" != ".." ]]',
            ),
            (
                self.formal.replace(
                    "d) ((DIRECTORY_COUNT += 1)) ;;\n",
                    "d|h|b|c|p) ((DIRECTORY_COUNT += 1)) ;;\n",
                    1,
                ),
                "d) ((DIRECTORY_COUNT += 1)) ;;",
            ),
            (
                self.formal.replace("            --no-same-owner \\\n", "", 1),
                "--no-same-owner",
            ),
            (
                self.formal.replace(
                    '/usr/bin/find "$JAVA_HOME" -xdev -type l -print -quit',
                    '/usr/bin/find "$JAVA_HOME" -xdev -type l -delete',
                    1,
                ),
                "type l -print -quit",
            ),
        )
        for mutation, diagnostic in mutations:
            with self.subTest(diagnostic=diagnostic):
                problems = CI_POLICY.verify_formal_job(
                    mutation,
                    label="formal",
                    pins=self.formal_pins,
                )
                self.assertTrue(
                    any(diagnostic in problem for problem in problems),
                    problems,
                )

    def test_formal_legal_links_have_an_exact_excluded_manifest(self) -> None:
        count_check = '[[ "$LINK_COUNT" -eq "$JAVA_LEGAL_LINK_COUNT" ]]'
        target_check = '[[ "$LINK_TARGET" == "../java.base/$LINK_NAME" ]]'
        link_location = '[[ "$LINK_PATH" == "$JAVA_ARCHIVE_ROOT/legal/"* ]]'
        mutations = (
            (
                self.formal.replace(count_check, count_check.replace("-eq", "-ge"), 1),
                count_check,
            ),
            (
                self.formal.replace(count_check, count_check.replace("-eq", "-le"), 1),
                count_check,
            ),
            (
                self.formal.replace(
                    link_location,
                    '[[ "$LINK_PATH" == "$JAVA_ARCHIVE_ROOT/"* ]]',
                    1,
                ),
                link_location,
            ),
            (
                self.formal.replace(
                    target_check,
                    '[[ "$LINK_TARGET" == "/java.base/$LINK_NAME" ]]',
                    1,
                ),
                target_check,
            ),
            (
                self.formal.replace(
                    target_check,
                    '[[ "$LINK_TARGET" == "../../java.base/$LINK_NAME" ]]',
                    1,
                ),
                target_check,
            ),
            (
                self.formal.replace(
                    target_check,
                    '[[ "$LINK_TARGET" == "../java.desktop/$LINK_NAME" ]]',
                    1,
                ),
                target_check,
            ),
            (
                self.formal.replace(
                    "e623b66f52db07699c4723e448b1a34531097e6c38ee63630da3dcd81729d576",
                    "0" * 64,
                    1,
                ),
                "e623b66f52db07699c4723e448b1a345",
            ),
            (
                self.formal.replace(
                    '            --exclude="${JAVA_ARCHIVE_ROOT}/legal" \\\n',
                    "",
                    1,
                ).replace(
                    '            --exclude="${JAVA_ARCHIVE_ROOT}/legal/*" \\\n',
                    "",
                    1,
                ),
                "--exclude=",
            ),
        )
        for mutation, diagnostic in mutations:
            with self.subTest(diagnostic=diagnostic):
                problems = CI_POLICY.verify_formal_job(
                    mutation,
                    label="formal",
                    pins=self.formal_pins,
                )
                self.assertTrue(
                    any(diagnostic in problem for problem in problems),
                    problems,
                )

    def test_formal_archive_identity_and_runtime_checks_are_fail_closed(self) -> None:
        mutations = (
            (
                self.formal.replace(
                    '/usr/bin/test ! -L "$JAVA_ARCHIVE"\n',
                    "",
                    1,
                ),
                '/usr/bin/test ! -L "$JAVA_ARCHIVE"',
            ),
            (
                self.formal.replace(
                    "| /usr/bin/sha256sum --check --strict\n",
                    "| /usr/bin/sha256sum --check\n",
                    1,
                ),
                "sha256sum --check --strict",
            ),
            (
                self.formal.replace(
                    "count != 1 || matches != 1",
                    "count < 1 || matches < 1",
                    1,
                ),
                "count != 1 || matches != 1",
            ),
            (
                self.formal.replace(
                    'assert_property java.runtime.version "$JAVA_RUNTIME_VERSION"\n',
                    "",
                    1,
                ),
                "assert_property java.runtime.version",
            ),
            (
                self.formal.replace(
                    "      - name: Fetch and install pinned Temurin JRE\n",
                    "      - uses: actions/setup-java@"
                    "03ad4de0992f5dab5e18fcb136590ce7c4a0ac95\n"
                    "      - name: Fetch and install pinned Temurin JRE\n",
                    1,
                ),
                "actions/setup-java",
            ),
        )
        for mutation, diagnostic in mutations:
            with self.subTest(diagnostic=diagnostic):
                problems = CI_POLICY.verify_formal_job(
                    mutation,
                    label="formal",
                    pins=self.formal_pins,
                )
                self.assertTrue(
                    any(diagnostic in problem for problem in problems),
                    problems,
                )


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
