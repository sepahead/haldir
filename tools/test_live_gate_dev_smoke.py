"""Offline structural tests for the development live Gate smoke runner."""

from __future__ import annotations

import io
import json
import hashlib
import os
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_gate_dev_smoke import (
    BUILDER_IMAGE,
    BUILD_TIMEOUT_SECONDS,
    EXPECTED_ROUTER_IMAGE,
    EXAMPLE_EXECUTABLES,
    GATE_SECRET_FILES,
    GENERATOR_ACTIONS,
    MANIFEST_SCHEMA_VERSION,
    MAX_BIND_ARCHIVE_BYTES,
    MAX_BIND_RESULT_BYTES,
    MAX_PROVISION_FILE_BYTES,
    PROVISION_ARCHIVE_DIRECTORIES,
    PROVISION_ARCHIVE_FILES,
    ROOT,
    SAFE_OUTPUT_ROOT,
    CampaignError,
    build_candidate,
    cleanup_runtime,
    copy_bind_result,
    extract_bind_result_archive,
    extract_provision_archive,
    hash_copied_example_executables,
    isolate_gate_secrets,
    require_safe_output,
    resolve_image_id,
    validate_result,
    wait_for_exit_marker,
)


class LiveGateDevSmokeTests(unittest.TestCase):
    @staticmethod
    def bind_result_archive(
        *,
        name: str | None = "bind-result.json",
        data: bytes = b'{"status":"pass"}\n',
        member_type: bytes = tarfile.REGTYPE,
        duplicate: bool = False,
        extra: str | None = None,
        wrong_owner: bool = False,
        wrong_group: bool = False,
        wrong_mode: bool = False,
    ) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            if name is not None:
                member = tarfile.TarInfo(name)
                member.type = member_type
                member.mode = 0o644 if wrong_mode else 0o600
                member.uid = os.getuid() + (1 if wrong_owner else 0)
                member.gid = os.getgid() + (1 if wrong_group else 0)
                if member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    member.linkname = "elsewhere"
                    archive.addfile(member)
                else:
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                if duplicate:
                    repeated = tarfile.TarInfo(name)
                    repeated.mode = 0o600
                    repeated.uid = os.getuid()
                    repeated.gid = os.getgid()
                    repeated.size = len(data)
                    archive.addfile(repeated, io.BytesIO(data))
            if extra is not None:
                unexpected = tarfile.TarInfo(extra)
                unexpected.mode = 0o600
                unexpected.uid = os.getuid()
                unexpected.gid = os.getgid()
                unexpected.size = len(data)
                archive.addfile(unexpected, io.BytesIO(data))
        return output.getvalue()

    @staticmethod
    def provision_archive(
        *,
        missing: str | None = None,
        extra: str | None = None,
        symlink: str | None = None,
        duplicate: str | None = None,
        wrong_owner: str | None = None,
        wrong_mode: str | None = None,
        contiguous: str | None = None,
        oversized: str | None = None,
    ) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name in sorted(PROVISION_ARCHIVE_DIRECTORIES):
                if name == missing:
                    continue
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                member.mode = 0o700
                member.uid = os.getuid()
                member.gid = os.getgid()
                archive.addfile(member)
            for name in sorted(PROVISION_ARCHIVE_FILES):
                if name == missing:
                    continue
                member = tarfile.TarInfo(name)
                member.mode = 0o644 if name == wrong_mode else 0o600
                member.uid = os.getuid() + (1 if name == wrong_owner else 0)
                member.gid = os.getgid()
                if name == symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "gate/state/generation.anchor"
                    archive.addfile(member)
                    continue
                if name == contiguous:
                    member.type = tarfile.CONTTYPE
                data = (
                    b"x" * (MAX_PROVISION_FILE_BYTES + 1)
                    if name == oversized
                    else b""
                    if name.endswith(".lock")
                    else name.encode()
                )
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
                if name == duplicate:
                    repeated = tarfile.TarInfo(name)
                    repeated.mode = 0o600
                    repeated.uid = os.getuid()
                    repeated.gid = os.getgid()
                    repeated.size = len(data)
                    archive.addfile(repeated, io.BytesIO(data))
            if extra is not None:
                data = b"unexpected"
                member = tarfile.TarInfo(extra)
                member.mode = 0o600
                member.uid = os.getuid()
                member.gid = os.getgid()
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return output.getvalue()

    def test_dockerfile_builds_both_examples_from_the_pinned_image(self) -> None:
        dockerfile = (ROOT / "tools" / "live-gate-dev-smoke" / "Dockerfile").read_text()
        self.assertEqual(dockerfile.count(f"FROM {BUILDER_IMAGE}"), 2)
        self.assertIn("--example live_gate_dev_fixture_provision", dockerfile)
        self.assertIn("--example live_gate_dev_bind_shutdown", dockerfile)
        self.assertIn("--features live-gate-dev-smoke", dockerfile)
        self.assertRegex(EXPECTED_ROUTER_IMAGE, r"@sha256:[0-9a-f]{64}$")
        self.assertEqual(BUILD_TIMEOUT_SECONDS, 3600)

    def test_raw_output_is_confined_to_its_ignored_target_subtree(self) -> None:
        safe = SAFE_OUTPUT_ROOT / "unit-new-output"
        self.assertEqual(require_safe_output(safe), safe.resolve())
        with self.assertRaises(CampaignError):
            require_safe_output(ROOT / "evidence" / "unsafe-live-output")

    def test_gate_mount_contains_only_gate_identity_and_ca(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clients = root / "clients"
            clients.mkdir()
            for name in (*GATE_SECRET_FILES, "controller-a.key.pem"):
                (clients / name).write_text(name)
            gate = isolate_gate_secrets(clients, root)
            self.assertEqual({path.name for path in gate.iterdir()}, GATE_SECRET_FILES)

    def test_built_example_hash_set_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = {}
            for index, name in enumerate(sorted(EXAMPLE_EXECUTABLES), start=1):
                data = bytes([index]) * index
                (root / name).write_bytes(data)
                expected[name] = hashlib.sha256(data).hexdigest()
            self.assertEqual(hash_copied_example_executables(root), expected)
            unexpected = root / "unexpected"
            unexpected.write_bytes(b"drift")
            with self.assertRaises(CampaignError):
                hash_copied_example_executables(root)
            unexpected.unlink()

            replaced = root / sorted(EXAMPLE_EXECUTABLES)[0]
            original = replaced.read_bytes()
            replaced.unlink()
            with self.assertRaises(CampaignError):
                hash_copied_example_executables(root)
            replaced.write_bytes(b"")
            with self.assertRaises(CampaignError):
                hash_copied_example_executables(root)
            replaced.unlink()
            replaced.symlink_to(root / sorted(EXAMPLE_EXECUTABLES)[1])
            with self.assertRaises(CampaignError):
                hash_copied_example_executables(root)
            replaced.unlink()
            replaced.write_bytes(original)
            self.assertEqual(hash_copied_example_executables(root), expected)

    def test_exact_provision_archive_is_reconstructed_with_restricted_modes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "provisioned"
            extract_provision_archive(
                self.provision_archive(),
                destination,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
            actual = {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*")
            }
            self.assertEqual(
                actual, PROVISION_ARCHIVE_DIRECTORIES | PROVISION_ARCHIVE_FILES
            )
            for name in PROVISION_ARCHIVE_DIRECTORIES:
                mode = stat.S_IMODE(
                    destination.joinpath(*name.split("/")).stat().st_mode
                )
                self.assertEqual(mode, 0o700)
            for name in PROVISION_ARCHIVE_FILES:
                path = destination.joinpath(*name.split("/"))
                mode = stat.S_IMODE(path.stat().st_mode)
                self.assertEqual(mode, 0o600)
                expected = b"" if name.endswith(".lock") else name.encode()
                self.assertEqual(path.read_bytes(), expected)

    def test_provision_archive_rejects_shape_and_type_attacks(self) -> None:
        first_file = sorted(PROVISION_ARCHIVE_FILES)[0]
        cases = {
            "missing": self.provision_archive(missing=first_file),
            "extra": self.provision_archive(extra="gate/unexpected"),
            "traversal": self.provision_archive(extra="../escape"),
            "absolute": self.provision_archive(extra="/escape"),
            "symlink": self.provision_archive(symlink=first_file),
            "duplicate": self.provision_archive(duplicate=first_file),
            "wrong owner": self.provision_archive(wrong_owner=first_file),
            "wrong mode": self.provision_archive(wrong_mode=first_file),
            "contiguous file": self.provision_archive(contiguous=first_file),
            "oversized": self.provision_archive(oversized=first_file),
            "truncated": b"not a tar archive",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, archive in cases.items():
                with self.subTest(label=label):
                    destination = root / label
                    with self.assertRaises(CampaignError):
                        extract_provision_archive(
                            archive,
                            destination,
                            expected_uid=os.getuid(),
                            expected_gid=os.getgid(),
                        )
                    self.assertFalse(destination.exists())

    def test_provision_archive_never_replaces_an_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "provisioned"
            destination.mkdir()
            sentinel = destination / "sentinel"
            sentinel.write_text("preserve")
            with self.assertRaises(CampaignError):
                extract_provision_archive(
                    self.provision_archive(),
                    destination,
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )
            self.assertEqual(sentinel.read_text(), "preserve")

    def test_exact_bind_result_archive_is_extracted_restricted(self) -> None:
        data = b'{"status":"pass"}\n'
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bind-result.json"
            extract_bind_result_archive(
                self.bind_result_archive(data=data),
                destination,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
            self.assertEqual(destination.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_bind_result_export_uses_one_exact_bounded_tar_stream(self) -> None:
        archive = self.bind_result_archive()

        class Runner:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], dict[str, object]]] = []

            def run_bytes(
                self, argv: list[str], **kwargs: object
            ) -> SimpleNamespace:
                self.calls.append((argv, kwargs))
                return SimpleNamespace(stdout=archive)

        runner = Runner()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bind-result.json"
            copy_bind_result(
                runner,
                gate_container="gate-container",
                destination=destination,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
            self.assertTrue(destination.is_file())
        self.assertEqual(
            runner.calls,
            [
                (
                    [
                        "docker",
                        "exec",
                        "gate-container",
                        "tar",
                        "-C",
                        "/evidence",
                        "-cf",
                        "-",
                        "bind-result.json",
                    ],
                    {
                        "max_stdout_bytes": MAX_BIND_ARCHIVE_BYTES,
                        "timeout_seconds": 60,
                    },
                )
            ],
        )

    def test_bind_result_archive_rejects_shape_and_type_attacks(self) -> None:
        cases = {
            "missing": self.bind_result_archive(name=None),
            "extra": self.bind_result_archive(extra="unexpected"),
            "traversal": self.bind_result_archive(name="../bind-result.json"),
            "absolute": self.bind_result_archive(name="/bind-result.json"),
            "symlink": self.bind_result_archive(member_type=tarfile.SYMTYPE),
            "hardlink": self.bind_result_archive(member_type=tarfile.LNKTYPE),
            "directory": self.bind_result_archive(member_type=tarfile.DIRTYPE),
            "fifo": self.bind_result_archive(member_type=tarfile.FIFOTYPE),
            "duplicate": self.bind_result_archive(duplicate=True),
            "wrong owner": self.bind_result_archive(wrong_owner=True),
            "wrong group": self.bind_result_archive(wrong_group=True),
            "wrong mode": self.bind_result_archive(wrong_mode=True),
            "contiguous file": self.bind_result_archive(member_type=tarfile.CONTTYPE),
            "empty file": self.bind_result_archive(data=b""),
            "oversized file": self.bind_result_archive(
                data=b"x" * (MAX_BIND_RESULT_BYTES + 1)
            ),
            "truncated": b"not a tar archive",
            "oversized archive": b"x" * (MAX_BIND_ARCHIVE_BYTES + 1),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, archive in cases.items():
                with self.subTest(label=label):
                    destination = root / label
                    with self.assertRaises(CampaignError):
                        extract_bind_result_archive(
                            archive,
                            destination,
                            expected_uid=os.getuid(),
                            expected_gid=os.getgid(),
                        )
                    self.assertFalse(destination.exists())

    def test_bind_result_archive_never_replaces_an_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bind-result.json"
            destination.write_text("preserve")
            with self.assertRaises(CampaignError):
                extract_bind_result_archive(
                    self.bind_result_archive(),
                    destination,
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )
            self.assertEqual(destination.read_text(), "preserve")

    def test_bind_result_archive_reports_incomplete_failure_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bind-result.json"
            with patch("live_gate_dev_smoke.delete_directory", return_value=False):
                with self.assertRaisesRegex(CampaignError, "cleanup is incomplete"):
                    extract_bind_result_archive(
                        b"not a tar archive",
                        destination,
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )

    def test_exit_marker_wait_bounds_early_stop_logs_to_deadline(self) -> None:
        class Runner:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], dict[str, object]]] = []
                self.results = iter(
                    [
                        SimpleNamespace(returncode=1, stdout="", stderr=""),
                        SimpleNamespace(returncode=1, stdout="", stderr=""),
                        SimpleNamespace(returncode=0, stdout="", stderr="diagnostic"),
                    ]
                )

            def run(self, argv: list[str], **kwargs: object) -> SimpleNamespace:
                self.calls.append((argv, kwargs))
                return next(self.results)

        runner = Runner()
        with patch(
            "live_gate_dev_smoke.time.monotonic",
            side_effect=[100.0, 100.0, 101.0, 104.0],
        ):
            with self.assertRaisesRegex(CampaignError, "diagnostic"):
                wait_for_exit_marker(
                    runner,
                    "container",
                    marker_path="/run/result",
                    label="target",
                    timeout_seconds=5,
                )
        self.assertEqual(
            [call[1]["timeout_seconds"] for call in runner.calls],
            [5.0, 4.0, 1.0],
        )

    def test_manifest_generator_actions_are_location_neutral(self) -> None:
        self.assertEqual(MANIFEST_SCHEMA_VERSION, 2)
        self.assertEqual(
            GENERATOR_ACTIONS,
            {
                "independent_verification_performed": False,
                "promotion_performed": False,
            },
        )

    def test_built_tag_is_resolved_to_an_immutable_image_id(self) -> None:
        class Runner:
            def __init__(self, stdout: str) -> None:
                self.stdout = stdout

            def run(self, _argv: list[str], **_kwargs: object) -> SimpleNamespace:
                return SimpleNamespace(stdout=self.stdout)

        image_id = "sha256:" + "c" * 64
        self.assertEqual(
            resolve_image_id(Runner(image_id + "\n"), "smoke:tag"), image_id
        )
        with self.assertRaises(CampaignError):
            resolve_image_id(Runner("smoke:tag\n"), "smoke:tag")

    def test_manifest_v2_binds_source_config_and_built_examples(self) -> None:
        cargo_lock = b"locked-source\n"
        dockerfile = b"FROM pinned@sha256:fixture\n"
        gate_config = b'{"mode":"client"}\n'
        executable_hashes = {
            name: hashlib.sha256(name.encode()).hexdigest()
            for name in EXAMPLE_EXECUTABLES
        }
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            source = work / "source"
            dockerfile_path = source / "tools" / "live-gate-dev-smoke"
            dockerfile_path.mkdir(parents=True)
            (source / "Cargo.lock").write_bytes(cargo_lock)
            (dockerfile_path / "Dockerfile").write_bytes(dockerfile)
            rendered = work / "rendered" / "clients"
            rendered.mkdir(parents=True)
            (rendered / "gate.json").write_bytes(gate_config)
            raw = work / "raw"
            raw.mkdir()
            for name, value in {
                "provision-result.json": {"mode": "provision"},
                "bind-result.json": {"mode": "bind"},
            }.items():
                (raw / name).write_text(json.dumps(value))
            for name in (
                "provision.stdout.log",
                "provision.stderr.log",
                "bind.stdout.log",
                "bind.stderr.log",
                "router.log",
            ):
                (raw / name).write_text("")

            output = build_candidate(
                work=work,
                source_commit="a" * 40,
                source_snapshot_sha256="b" * 64,
                profile={
                    "profile_id": "haldir-secure-reference-v1",
                    "router": {"image": EXPECTED_ROUTER_IMAGE},
                },
                profile_bytes=b"profile\n",
                started_at="2026-07-13T00:00:00Z",
                finished_at="2026-07-13T00:00:01Z",
                cleanup={"all_objects_removed": True},
                private_cleanup=True,
                fixture_cleanup=True,
                example_executable_sha256=executable_hashes,
                smoke_image_id="sha256:" + "c" * 64,
                commands=[],
                pki_inventory={},
                pki_log="",
                docker_metadata={},
            )
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(
                manifest["cargo_lock_sha256"], hashlib.sha256(cargo_lock).hexdigest()
            )
            self.assertEqual(
                manifest["dockerfile_sha256"], hashlib.sha256(dockerfile).hexdigest()
            )
            self.assertEqual(
                manifest["gate_config_sha256"],
                hashlib.sha256(gate_config).hexdigest(),
            )
            self.assertEqual(manifest["example_executable_sha256"], executable_hashes)
            self.assertEqual(manifest["smoke_image_id"], "sha256:" + "c" * 64)
            self.assertNotIn("candidate_status", manifest)
            readme = (output / "README.md").read_text()
            self.assertNotIn("not retained", readme)
            self.assertNotIn("under `target/`", readme)

    def test_results_require_provision_new_then_zero_processing_open_existing(
        self,
    ) -> None:
        common = {
            "development_only": True,
            "ncp_wire_profile": "exact-ncp-v0.8-json",
            "production_claim": False,
            "runtime_profile": "declared-live-zenoh",
            "schema_version": 1,
            "status": "pass",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provision = root / "provision.json"
            provision.write_text(
                json.dumps(
                    {
                        **common,
                        "mode": "development-live-fixture-provision-v1",
                        "provisioned": True,
                    }
                )
            )
            validate_result(provision, provision=True)

            bind = root / "bind.json"
            bind_value = {
                **common,
                "mode": "development-live-bind-smoke-v1",
                "provisioned": False,
                "negative_evidence": {
                    "commands_published_by_target": 0,
                    "intents_processed_by_target": 0,
                },
                "local_returns": {
                    "aggregate_bind": True,
                    "aggregate_shutdown": True,
                    "session_open": True,
                },
            }
            bind.write_text(json.dumps(bind_value))
            validate_result(bind, provision=False)
            bind_value["negative_evidence"]["intents_processed_by_target"] = 1
            bind.write_text(json.dumps(bind_value))
            with self.assertRaises(CampaignError):
                validate_result(bind, provision=False)

    def test_cleanup_attempts_every_docker_object_after_a_failure(self) -> None:
        class Runner:
            def __init__(self) -> None:
                self.calls = 0

            def run(self, _argv: list[str], **_kwargs: object) -> SimpleNamespace:
                self.calls += 1
                if self.calls == 1:
                    raise CampaignError("simulated stuck Gate container")
                return SimpleNamespace(returncode=0)

        runner = Runner()
        outcomes = cleanup_runtime(
            runner,
            inspector_container="inspector",
            provision_container="provision",
            gate_container="gate",
            router_container="router",
            network="network",
            smoke_image="image",
        )
        self.assertEqual(runner.calls, 6)
        self.assertFalse(outcomes["gate_container_removed"])
        self.assertTrue(outcomes["smoke_image_removed"])


if __name__ == "__main__":
    unittest.main()
