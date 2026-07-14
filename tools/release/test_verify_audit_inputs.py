#!/usr/bin/env python3
"""Positive, negative, boundary, adversarial, and regression tests for T000."""

from __future__ import annotations

import copy
import gzip
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("verify-audit-inputs.py")
SPEC = importlib.util.spec_from_file_location("verify_audit_inputs", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class AuditInputVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[2]
        cls.manifest_path = cls.repo / "release/0.9.0/audit-inputs.json"
        cls.manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

    def write_manifest(self, value: dict[str, object], directory: str) -> Path:
        path = Path(directory) / "audit-inputs.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_positive_exact_audit_cut_verifies(self) -> None:
        VERIFY.verify(self.manifest_path, self.repo)

    def test_negative_handoff_digest_tampering_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["handoff"]["files"][0]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_manifest(value, directory)
            with self.assertRaisesRegex(VERIFY.AuditError, "AUDIT_HANDOFF_DIGEST_MISMATCH"):
                VERIFY.verify(path, self.repo)

    def test_regression_source_commit_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["source"]["commit"] = "0" * 40
        value["source"]["origin_main_commit"] = "0" * 40
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_manifest(value, directory)
            with self.assertRaisesRegex(VERIFY.AuditError, "AUDIT_GIT_LOOKUP_FAILED"):
                VERIFY.verify(path, self.repo)

    def test_boundary_oversized_manifest_is_rejected_before_json_decode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit-inputs.json"
            path.write_bytes(b"{" + b" " * VERIFY.MAX_MANIFEST_BYTES + b"}")
            with self.assertRaisesRegex(VERIFY.AuditError, "AUDIT_RESOURCE_BOUND"):
                VERIFY.verify(path, self.repo)

    def test_adversarial_decompression_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.log.gz"
            with path.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as handle:
                    handle.write(b"x" * 65)
            with self.assertRaisesRegex(VERIFY.AuditError, "AUDIT_LOG_RESOURCE_BOUND"):
                VERIFY.read_bounded_gzip(path, limit=64)

    def test_negative_duplicate_handoff_path_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["handoff"]["files"][1]["path"] = value["handoff"]["files"][0]["path"]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_manifest(value, directory)
            with self.assertRaisesRegex(VERIFY.AuditError, "DUPLICATE"):
                VERIFY.verify(path, self.repo)


if __name__ == "__main__":
    unittest.main()
