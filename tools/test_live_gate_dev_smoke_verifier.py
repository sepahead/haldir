"""Offline unit tests for the independent live-Gate smoke verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "haldir_live_gate_dev_smoke_verifier",
    Path(__file__).resolve().parent / "verify-live-gate-dev-smoke.py",
)
if VERIFIER_SPEC is None or VERIFIER_SPEC.loader is None:
    raise RuntimeError("cannot load live Gate smoke verifier")
VERIFIER = importlib.util.module_from_spec(VERIFIER_SPEC)
VERIFIER_SPEC.loader.exec_module(VERIFIER)


def write_checksums(root: Path, relatives: list[str]) -> None:
    lines = [
        f"{hashlib.sha256((root / relative).read_bytes()).hexdigest()}  {relative}"
        for relative in sorted(relatives)
    ]
    (root / "checksums.sha256").write_text("\n".join(lines) + "\n")


def journal(*, provision: bool) -> dict[str, object]:
    return {
        "active_sequence": 1 if provision else 2,
        "closed_active_tail": not provision,
        "completed_segments": 0 if provision else 1,
        "discarded_pending_creation": False,
        "discovered_segments": 0 if provision else 1,
        "quiesced": False,
        "recovered_records": 0,
        "recovery_unknown_events": 0,
        "total_bytes": 100 if provision else 200,
        "truncated_tail_bytes": 0,
    }


def provision_result() -> dict[str, object]:
    return {
        "anchor_protection": "local-rewritable",
        "development_only": True,
        "journal": journal(provision=True),
        "mode": "development-live-fixture-provision-v1",
        "ncp_wire_profile": "exact-ncp-v0.8-json",
        "production_claim": False,
        "provisioned": True,
        "runtime_profile": "declared-live-zenoh",
        "schema_version": 1,
        "stages": VERIFIER.PROVISION_STAGES,
        "startup_generation": 2,
        "status": "pass",
    }


def bind_result(intent_route: str) -> dict[str, object]:
    return {
        "anchor_protection": "local-rewritable",
        "bind_returned_ok": True,
        "controller_id": "controller-a",
        "development_only": True,
        "discarded_events": 0,
        "gate_boot_id": [1] * 16,
        "gate_output_epoch": [2] * 16,
        "ingress_counters": {key: 0 for key in VERIFIER.INGRESS_COUNTER_KEYS},
        "intent_route": intent_route,
        "journal": journal(provision=False),
        "lease_term": 3,
        "local_returns": {
            "aggregate_bind": True,
            "aggregate_shutdown": True,
            "session_open": True,
        },
        "mode": "development-live-bind-smoke-v1",
        "ncp_wire_profile": "exact-ncp-v0.8-json",
        "negative_evidence": dict(VERIFIER.NEGATIVE_EVIDENCE),
        "production_claim": False,
        "provisioned": False,
        "runtime_profile": "declared-live-zenoh",
        "schema_version": 1,
        "shutdown_returned_ok": True,
        "stages": VERIFIER.BIND_STAGES,
        "startup_generation": 3,
        "startup_recovery": "clean",
        "status": "pass",
        "zid": {
            "authenticated_principal": False,
            "operational_identifier": "zid-for-test",
        },
    }


class LiveGateDevSmokeVerifierTests(unittest.TestCase):
    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"status": "pass", "status": "fail"}\n')
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.load_json(path)

    def test_checksum_coverage_rejects_a_missing_nested_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nested").mkdir()
            (root / "README.md").write_text("readme\n")
            (root / "nested" / "result.json").write_text("{}\n")
            write_checksums(root, ["README.md"])
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.verify_checksums(root)

    def test_checksum_verification_rejects_post_manifest_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.json"
            artifact.write_text('{"status":"pass"}\n')
            write_checksums(root, ["artifact.json"])
            VERIFIER.verify_checksums(root)
            artifact.write_text('{"status":"fail"}\n')
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.verify_checksums(root)

    def test_result_mutation_breaks_zero_publication_boundary(self) -> None:
        profile = VERIFIER.load_profile(VERIFIER.DEFAULT_PROFILE)
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            results = evidence / "results"
            results.mkdir()
            provision = provision_result()
            bind = bind_result(profile["routes"]["controller_a_intent"])
            (results / "provision-result.json").write_bytes(
                VERIFIER.canonical_json(provision)
            )
            (results / "bind-result.json").write_bytes(VERIFIER.canonical_json(bind))
            verified_provision = VERIFIER.verify_provision_result(evidence)
            VERIFIER.verify_bind_result(evidence, profile, verified_provision)
            bind["negative_evidence"]["commands_published_by_target"] = 1
            (results / "bind-result.json").write_bytes(VERIFIER.canonical_json(bind))
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.verify_bind_result(evidence, profile, verified_provision)


if __name__ == "__main__":
    unittest.main()
