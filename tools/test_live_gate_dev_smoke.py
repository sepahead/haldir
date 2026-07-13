"""Offline structural tests for the development live Gate smoke runner."""

from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_gate_dev_smoke import (
    BUILDER_IMAGE,
    BUILD_TIMEOUT_SECONDS,
    EXPECTED_ROUTER_IMAGE,
    EXAMPLE_EXECUTABLES,
    GATE_SECRET_FILES,
    GENERATOR_ACTIONS,
    MANIFEST_SCHEMA_VERSION,
    ROOT,
    SAFE_OUTPUT_ROOT,
    CampaignError,
    build_candidate,
    cleanup_runtime,
    hash_copied_example_executables,
    isolate_gate_secrets,
    require_safe_output,
    resolve_image_id,
    validate_result,
)


class LiveGateDevSmokeTests(unittest.TestCase):
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
