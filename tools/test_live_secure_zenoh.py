"""Offline structural tests for the live secure-Zenoh campaign harness."""

from __future__ import annotations

import json
import importlib.util
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_secure_zenoh import (
    BUILDER_IMAGE,
    CampaignError,
    CommandRunner,
    EXPECTED_ROUTER_IMAGE,
    ROOT,
    canonical_json,
    cleanup_runtime,
    remove_private_material,
    require_safe_output,
    sanitize_value,
    scan_candidate,
    write_no_certificate_config,
)
from secure_zenoh import load_profile, render_bundle, write_bundle

VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "haldir_live_evidence_verifier",
    Path(__file__).resolve().parent / "verify-live-secure-zenoh.py",
)
if VERIFIER_SPEC is None or VERIFIER_SPEC.loader is None:
    raise RuntimeError("cannot load live evidence verifier")
VERIFIER = importlib.util.module_from_spec(VERIFIER_SPEC)
VERIFIER_SPEC.loader.exec_module(VERIFIER)


class LiveSecureZenohHarnessTests(unittest.TestCase):
    def test_binary_command_output_is_preserved_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = CommandRunner(Path(temporary))
            result = runner.run_bytes(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(bytes([0, 255, 1]))",
                ],
                max_stdout_bytes=3,
            )
            self.assertEqual(result.stdout, bytes([0, 255, 1]))
            self.assertEqual(runner.commands[0]["exit_code"], 0)

            with self.assertRaises(CampaignError):
                runner.run_bytes(
                    [sys.executable, "-c", "print('unbounded-output')"],
                    max_stdout_bytes=3,
                )
            self.assertEqual(runner.commands[1]["exit_code"], "stdout-limit")
            self.assertEqual(runner.commands[1]["max_stdout_bytes"], 3)

            with self.assertRaises(CampaignError) as failure:
                runner.run_bytes(
                    [
                        sys.executable,
                        "-c",
                        f"import sys; sys.stderr.write({str(Path(temporary))!r}); sys.exit(7)",
                    ],
                    max_stdout_bytes=3,
                )
            self.assertIn("$WORK", str(failure.exception))
            self.assertNotIn(str(Path(temporary)), str(failure.exception))
            self.assertEqual(runner.commands[2]["exit_code"], 7)

            with self.assertRaises(CampaignError):
                runner.run_bytes(
                    [sys.executable, "-c", "import time; time.sleep(2)"],
                    max_stdout_bytes=3,
                    timeout_seconds=1,
                )
            self.assertEqual(runner.commands[3]["exit_code"], "timeout")

    def test_images_are_immutable_digests_and_match_profile(self) -> None:
        self.assertRegex(BUILDER_IMAGE, r"@sha256:[0-9a-f]{64}$")
        self.assertRegex(EXPECTED_ROUTER_IMAGE, r"@sha256:[0-9a-f]{64}$")
        profile = load_profile(ROOT / "deploy" / "secure-reference-v1" / "profile.json")
        self.assertEqual(profile["router"]["image"], EXPECTED_ROUTER_IMAGE)

    def test_raw_output_is_confined_to_ignored_target_tree(self) -> None:
        safe = ROOT / "target" / "live-secure-zenoh" / "unit-new-output"
        self.assertEqual(require_safe_output(safe), safe.resolve())
        with self.assertRaises(CampaignError):
            require_safe_output(ROOT / "evidence" / "unsafe-live-output")

    def test_sanitization_recurses_without_changing_non_strings(self) -> None:
        work = ROOT / "target" / "live-secure-zenoh" / "unit"
        value = {"paths": [str(work / "raw"), str(ROOT / "Cargo.toml")], "count": 2}
        self.assertEqual(
            sanitize_value(value, work),
            {"paths": ["$WORK/raw", "$REPO/Cargo.toml"], "count": 2},
        )

    def test_no_certificate_fixture_removes_both_identity_paths(self) -> None:
        profile = load_profile(ROOT / "deploy" / "secure-reference-v1" / "profile.json")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            rendered = base / "rendered"
            write_bundle(rendered, render_bundle(profile))
            campaign = base / "campaign"
            write_no_certificate_config(rendered, campaign)
            config = json.loads((campaign / "no-certificate.json").read_text())
            tls = config["transport"]["link"]["tls"]
            self.assertNotIn("connect_certificate", tls)
            self.assertNotIn("connect_private_key", tls)
            self.assertFalse(tls["enable_mtls"])
            self.assertEqual(
                sorted(path.name for path in (campaign / "clients").iterdir()),
                sorted(path.name for path in (rendered / "clients").iterdir()),
            )

    def test_candidate_scanner_rejects_private_key_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            (evidence / "result.json").write_bytes(canonical_json({"status": "pass"}))
            scan_candidate(evidence)
            (evidence / "leak.pem").write_text(
                "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"
            )
            with self.assertRaises(CampaignError):
                scan_candidate(evidence)

    def test_cleanup_actions_are_failure_isolated_and_keys_are_removed(self) -> None:
        class Runner:
            def __init__(self) -> None:
                self.calls = 0

            def run(self, _argv: list[str], **_kwargs: object) -> SimpleNamespace:
                self.calls += 1
                if self.calls == 1:
                    raise CampaignError("simulated stuck probe cleanup")
                return SimpleNamespace(returncode=0)

        runner = Runner()
        outcomes = cleanup_runtime(
            runner, "router", "probe", "network", "probe-image"
        )
        self.assertEqual(runner.calls, 4)
        self.assertFalse(outcomes["probe_container_removed"])
        self.assertTrue(outcomes["router_container_removed"])
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for name in ("pki-authority", "router-secrets", "client-secrets"):
                path = work / name
                path.mkdir()
                (path / "identity.key.pem").write_text("ephemeral")
            self.assertTrue(remove_private_material(work))
            self.assertFalse(any((work / name).exists() for name in (
                "pki-authority", "router-secrets", "client-secrets"
            )))

    def test_verifier_rejects_duplicate_json_and_nested_checksum_omission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"a": 1, "a": 2}\n')
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.load_json(duplicate)

            evidence = root / "evidence"
            (evidence / "logs").mkdir(parents=True)
            (evidence / "README.md").write_text("fixture\n")
            (evidence / "logs" / "checksums.sha256").write_text("nested\n")
            digest = hashlib.sha256((evidence / "README.md").read_bytes()).hexdigest()
            (evidence / "checksums.sha256").write_text(f"{digest}  README.md\n")
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.verify_checksums(evidence)


if __name__ == "__main__":
    unittest.main()
