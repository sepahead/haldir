#!/usr/bin/env python3
"""Tests for the CH-T003 public-surface inventory generator."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import time
import unittest
import warnings
import zipfile
import zlib
from pathlib import Path
from unittest import mock


def generator():
    cached = sys.modules.get("_haldir_public_surface_inventory")
    if cached is not None:
        return cached
    path = Path(__file__).with_name("current-public-surface-inventory.py")
    spec = importlib.util.spec_from_file_location(
        "_haldir_public_surface_inventory", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("generator import failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def zip_payload(members: list[tuple[str, bytes]], *, mode: int | None = None) -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for name, payload in members:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                if mode is not None:
                    info.create_system = 3
                    info.external_attr = mode << 16
                archive.writestr(info, payload)
    return target.getvalue()


def insert_before_zip_central_directory(payload: bytes, inserted: bytes) -> bytes:
    value = bytearray(payload)
    eocd = value.rfind(b"PK\x05\x06")
    central_offset = int.from_bytes(value[eocd + 16 : eocd + 20], "little")
    value[central_offset:central_offset] = inserted
    eocd += len(inserted)
    value[eocd + 16 : eocd + 20] = (central_offset + len(inserted)).to_bytes(
        4,
        "little",
    )
    return bytes(value)


def zip_payload_with_data_descriptor() -> bytes:
    value = bytearray(zip_payload([("member.txt", b"payload")]))
    local = value.find(b"PK\x03\x04")
    central = value.find(b"PK\x01\x02")
    crc_and_sizes = bytes(value[local + 14 : local + 26])
    value[local + 6 : local + 8] = (0x08).to_bytes(2, "little")
    value[local + 14 : local + 26] = b"\x00" * 12
    value[central + 8 : central + 10] = (0x08).to_bytes(2, "little")
    return insert_before_zip_central_directory(
        bytes(value),
        b"PK\x07\x08" + crc_and_sizes,
    )


def gzip_payload(payload: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=16 + zlib.MAX_WBITS)
    return compressor.compress(payload) + compressor.flush()


def claim_ledger_payload() -> bytes:
    module = generator()
    identifiers = [module.NARROWED_CLAIM]
    identifiers.extend(f"CL-TEST-{index:02d}" for index in range(1, 52))
    lines = []
    for index, identifier in enumerate(sorted(identifiers)):
        status = "PROVEN" if index < 45 else "UNPROVEN"
        statement = (
            "Narrow repository primitive."
            if identifier == module.NARROWED_CLAIM
            else "Statement."
        )
        lines.append(f"| {identifier} | {statement} | {status} | Evidence. |")
    return ("\n".join(lines) + "\n").encode()


def github_documents(freeze_commit: str = "a" * 40) -> dict[str, tuple[int, object]]:
    module = generator()
    repository = {
        "node_id": "R_1",
        "name": "haldir",
        "full_name": module.REPOSITORY,
        "description": "Experimental exact authorization project.",
        "homepage": None,
        "default_branch": "main",
        "private": False,
        "visibility": "public",
        "archived": False,
        "disabled": False,
        "fork": False,
        "is_template": False,
        "language": "Python",
        "size": 1,
        "open_issues_count": 0,
        "allow_forking": True,
        "web_commit_signoff_required": False,
        "owner": {"login": "sepahead"},
        "license": {"spdx_id": "Apache-2.0"},
        "security_and_analysis": {},
        "has_issues": True,
        "has_projects": True,
        "has_wiki": True,
        "has_pages": False,
        "has_discussions": False,
        "allow_squash_merge": True,
        "allow_merge_commit": True,
        "allow_rebase_merge": True,
        "allow_auto_merge": False,
        "delete_branch_on_merge": False,
        "use_squash_pr_title_as_default": False,
        "squash_merge_commit_title": "COMMIT_OR_PR_TITLE",
        "squash_merge_commit_message": "COMMIT_MESSAGES",
        "merge_commit_title": "MERGE_MESSAGE",
        "merge_commit_message": "PR_TITLE",
    }
    values: dict[str, tuple[int, object]] = {
        "repository": (200, repository),
        "topics": (200, {"names": []}),
        "community_profile": (200, {"health_percentage": 71, "files": {}}),
        "license": (200, {"license": {"spdx_id": "Apache-2.0", "name": "Apache"}}),
        "languages": (200, {"Python": 1}),
        "contributors": (200, []),
        "branches": (
            200,
            [
                {
                    "name": "main",
                    "protected": True,
                    "commit": {"sha": freeze_commit},
                }
            ],
        ),
        "main_protection": (200, {"enforce_admins": {"enabled": True}}),
        "rulesets": (200, []),
        "tags": (200, []),
        "releases": (200, []),
        "workflows": (200, {"total_count": 2, "workflows": []}),
        "actions_permissions": (200, {"enabled_repositories": "all"}),
        "workflow_token_permissions": (
            200,
            {
                "default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": False,
            },
        ),
        "environments": (200, {"total_count": 0, "environments": []}),
        "variables": (
            200,
            {
                "total_count": 1,
                "variables": [
                    {
                        "name": "SAFE_VARIABLE_NAME",
                        "value": "variable-value-must-not-survive",
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-02T00:00:00Z",
                    }
                ],
            },
        ),
        "secrets": (
            200,
            {
                "total_count": 1,
                "secrets": [
                    {
                        "name": "SAFE_NAME",
                        "created_at": "2026-01-01T00:00:00Z",
                        "value": "must-not-survive",
                    }
                ],
            },
        ),
        "pages": (404, {"message": "Not Found"}),
        "vulnerability_alerts": (404, {"message": "Not Found"}),
        "private_vulnerability_reporting": (404, {"message": "Not Found"}),
        "code_scanning_default_setup": (404, {"message": "Not Found"}),
        "hooks": (
            200,
            [
                {
                    "id": 1,
                    "active": True,
                    "config": {"url": "https://secret.invalid", "secret": "value"},
                }
            ],
        ),
        "deploy_keys": (200, [{"id": 1, "title": "key", "key": "ssh-ed25519 AAA"}]),
        "autolinks": (200, []),
        "interaction_limits": (404, {"message": "Not Found"}),
    }
    return values


def github_fetch(
    documents: dict[str, tuple[int, object]],
    *,
    next_for: str | None = None,
    evil_next: bool = False,
    cross_boundary_next: bool = False,
    etag_suffix: str = "",
):
    module = generator()
    calls: dict[str, int] = {}

    def fetch(url: str):
        endpoint = next(
            item["id"]
            for item in module.GITHUB_ENDPOINTS
            if url.split("?", 1)[0]
            == ("https://api.github.com" + item["endpoint"]).split("?", 1)[0]
        )
        calls[endpoint] = calls.get(endpoint, 0) + 1
        status, value = documents[endpoint]
        suffix = etag_suffix if endpoint in module.SENSITIVE_RAW_BODY_ENDPOINTS else ""
        headers: dict[str, str] = {"etag": f'"{endpoint}{suffix}"'}
        if endpoint == next_for and calls[endpoint] == 1:
            if isinstance(value, dict):
                collection_keys = [
                    key for key, item in value.items() if isinstance(item, list)
                ]
                if len(collection_keys) != 1:
                    raise AssertionError(f"no unique collection for {endpoint}")
                value = {
                    **value,
                    "total_count": 0,
                    collection_keys[0]: [],
                }
            else:
                value = []
            host = "evil.invalid" if evil_next else "api.github.com"
            repository = (
                f"{module.REPOSITORY}-other"
                if cross_boundary_next
                else module.REPOSITORY
            )
            specification = next(
                item for item in module.GITHUB_ENDPOINTS if item["id"] == endpoint
            )
            next_endpoint = specification["endpoint"].replace(
                module.REPOSITORY,
                repository,
                1,
            )
            separator = "&" if "?" in next_endpoint else "?"
            headers["link"] = (
                f'<https://{host}{next_endpoint}{separator}page=2>; rel="next"'
            )
        body = b"" if status == 204 else json.dumps(value).encode()
        return status, headers, body

    return fetch


class CanonicalAndPathTests(unittest.TestCase):
    def test_canonical_json_is_sorted_and_terminated(self):
        module = generator()
        self.assertEqual(module.canonical_json({"b": 2, "a": 1}), b'{"a":1,"b":2}\n')

    def test_canonical_json_rejects_nonfinite(self):
        module = generator()
        with self.assertRaises(ValueError):
            module.canonical_json({"value": float("nan")})

    def test_strict_json_accepts_one_key(self):
        module = generator()
        self.assertEqual(module.strict_json(b'{"a":1}', label="x"), {"a": 1})

    def test_strict_json_rejects_duplicate_key(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.strict_json(b'{"a":1,"a":2}', label="x")

    def test_strict_json_rejects_nonfinite(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.strict_json(b'{"a":NaN}', label="x")

    def test_valid_path_accepts_normal_relative_path(self):
        self.assertTrue(generator().valid_path("docs/CLAIM-LEDGER.md"))

    def test_valid_path_rejects_traversal(self):
        self.assertFalse(generator().valid_path("../escape"))

    def test_valid_path_rejects_backslash(self):
        self.assertFalse(generator().valid_path("a\\b"))

    def test_valid_path_rejects_nul(self):
        self.assertFalse(generator().valid_path("a\x00b"))

    def test_valid_path_rejects_non_nfc(self):
        self.assertFalse(generator().valid_path("e\u0301.txt"))

    def test_classification_is_explicit(self):
        module = generator()
        self.assertEqual(module.classify_path("README.md")[0], "PUBLIC_DOCUMENTATION")
        self.assertEqual(
            module.classify_path("crates/a/src/lib.rs")[0],
            "PUBLIC_API_OR_SCHEMA",
        )
        self.assertEqual(
            module.classify_path("release/x.json")[1],
            "EXCLUDED",
        )

    def test_classification_rejects_unknown_extension(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.classify_path("unknown/file.xyzzy")


class StructuredDataTests(unittest.TestCase):
    def test_yaml_unique_keys_pass(self):
        generator().validate_yaml_duplicate_keys(b"a: 1\nb: 2\n", "x.yml")

    def test_yaml_duplicate_keys_fail(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.validate_yaml_duplicate_keys(b"a: 1\na: 2\n", "x.yml")

    def test_yaml_nested_same_key_passes(self):
        generator().validate_yaml_duplicate_keys(
            b"a:\n  value: 1\nb:\n  value: 2\n", "x.yml"
        )

    def test_yaml_malformed_flow_fails(self):
        module = generator()
        for payload in (
            b"a: [unterminated\n",
            b"a: {key: 1, key: 2}\n",
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(module.InventoryError):
                    module.validate_yaml_duplicate_keys(payload, "x.yml")

    def test_yaml_rejects_child_below_scalar(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.validate_yaml_duplicate_keys(b"a: 1\n  b: 2\n", "x.yml")

    def test_yaml_rejects_plain_scalar_mapping_injection(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.validate_yaml_duplicate_keys(b"a: foo: bar\n", "x.yml")

    def test_yaml_rejects_invalid_double_quote_escape(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.validate_yaml_duplicate_keys(b'a: "\\q"\n', "x.yml")

    def test_yaml_rejects_lone_unicode_surrogate(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.validate_yaml_duplicate_keys(b'a: "\\ud800"\n', "x.yml")

    def test_yaml_rejects_duplicate_after_inline_sequence_block(self):
        module = generator()
        payload = (
            b"jobs:\n"
            b"  x:\n"
            b"    steps:\n"
            b"      - run: |\n"
            b"          echo ok\n"
            b"        run: duplicate\n"
        )
        with self.assertRaises(module.InventoryError):
            module.validate_yaml_duplicate_keys(payload, "x.yml")

    def test_current_workflows_pass_strict_yaml_subset(self):
        module = generator()
        for path in (
            Path(".github/workflows/ci.yml"),
            Path(".github/workflows/formal.yml"),
        ):
            with self.subTest(path=path.as_posix()):
                module.validate_yaml_duplicate_keys(path.read_bytes(), path.as_posix())

    def test_toml_duplicate_keys_fail(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.validate_toml_and_yaml("x.toml", b"a=1\na=2\n")

    def test_json5_is_strictly_parsed(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.validate_toml_and_yaml("x.json5", b'{"a":1,"a":2}\n')

    def test_content_kind_marks_archive_binary(self):
        self.assertEqual(generator().content_kind("x.zip", b"text"), "BINARY")

    def test_content_kind_marks_utf8(self):
        self.assertEqual(generator().content_kind("x.txt", b"text\n"), "UTF8")


class ArchiveTests(unittest.TestCase):
    def test_zip_enumerates_and_binds_member(self):
        module = generator()
        members, contents = module.zip_members(
            "x.zip", zip_payload([("safe/file.txt", b"hello")])
        )
        self.assertEqual(members[0]["sha256"], module.sha256(b"hello"))
        self.assertEqual(contents["safe/file.txt"], b"hello")

    def test_zip_rejects_traversal(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", zip_payload([("../escape", b"x")]))

    def test_zip_rejects_backslash(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", zip_payload([("a\\b", b"x")]))

    def test_zip_rejects_duplicate_member(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", zip_payload([("same", b"x"), ("same", b"y")]))

    def test_zip_rejects_symlink(self):
        module = generator()
        mode = stat.S_IFLNK | 0o777
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", zip_payload([("link", b"target")], mode=mode))

    def test_zip_rejects_oversized_declared_member(self):
        module = generator()
        payload = zip_payload([("x", b"small")])
        with mock.patch.object(module, "MAX_ARCHIVE_MEMBER_BYTES", 4):
            with self.assertRaises(module.InventoryError):
                module.zip_members("x.zip", payload)

    def test_zip_rejects_compression_bomb_ratio(self):
        module = generator()
        payload = zip_payload([("x", b"A" * 50_000)])
        with mock.patch.object(module, "MAX_COMPRESSION_RATIO", 2):
            with self.assertRaises(module.InventoryError):
                module.zip_members("x.zip", payload)

    def test_zip_rejects_encryption_flag(self):
        module = generator()
        payload = bytearray(zip_payload([("x", b"payload")]))
        local = payload.find(b"PK\x03\x04")
        central = payload.find(b"PK\x01\x02")
        payload[local + 6] |= 1
        payload[central + 8] |= 1
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", bytes(payload))

    def test_zip_rejects_reserved_flag(self):
        module = generator()
        payload = bytearray(zip_payload([("x", b"payload")]))
        local = payload.find(b"PK\x03\x04")
        central = payload.find(b"PK\x01\x02")
        payload[local + 6 : local + 8] = (0x10).to_bytes(2, "little")
        payload[central + 8 : central + 10] = (0x10).to_bytes(2, "little")
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", bytes(payload))

    def test_zip_rejects_unsupported_compression(self):
        module = generator()
        payload = bytearray(zip_payload([("x", b"payload")]))
        local = payload.find(b"PK\x03\x04")
        central = payload.find(b"PK\x01\x02")
        payload[local + 8 : local + 10] = (99).to_bytes(2, "little")
        payload[central + 10 : central + 12] = (99).to_bytes(2, "little")
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", bytes(payload))

    def test_zip_rejects_corrupt_crc(self):
        module = generator()
        payload = bytearray(zip_payload([("x", b"payload")]))
        local = payload.find(b"PK\x03\x04")
        central = payload.find(b"PK\x01\x02")
        payload[local + 14 : local + 18] = (0).to_bytes(4, "little")
        payload[central + 16 : central + 20] = (0).to_bytes(4, "little")
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", bytes(payload))

    def test_zip_accepts_exact_signed_data_descriptor(self):
        module = generator()
        members, contents = module.zip_members(
            "x.zip",
            zip_payload_with_data_descriptor(),
        )
        self.assertEqual([item["name"] for item in members], ["member.txt"])
        self.assertEqual(contents, {"member.txt": b"payload"})

    def test_zip_rejects_hidden_gap_before_central_directory(self):
        module = generator()
        payload = insert_before_zip_central_directory(
            zip_payload([("member.txt", b"payload")]),
            b"hidden-gap",
        )
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", payload)

    def test_zip_rejects_deflate_stream_tail(self):
        module = generator()
        value = bytearray(zip_payload([("member.txt", b"A")]))
        local = value.find(b"PK\x03\x04")
        compressed_size = int.from_bytes(value[local + 18 : local + 22], "little")
        compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
        tail = compressor.compress(b"B") + compressor.flush()
        value = bytearray(insert_before_zip_central_directory(bytes(value), tail))
        central = value.find(b"PK\x01\x02")
        value[local + 18 : local + 22] = (compressed_size + len(tail)).to_bytes(
            4,
            "little",
        )
        value[central + 20 : central + 24] = (compressed_size + len(tail)).to_bytes(
            4, "little"
        )
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", bytes(value))

    def test_zip_rejects_local_only_extra_field(self):
        module = generator()
        value = bytearray(zip_payload([("member.txt", b"payload")]))
        local = value.find(b"PK\x03\x04")
        eocd = value.rfind(b"PK\x05\x06")
        central_offset = int.from_bytes(value[eocd + 16 : eocd + 20], "little")
        name_length = int.from_bytes(value[local + 26 : local + 28], "little")
        data_start = local + 30 + name_length
        value[local + 28 : local + 30] = (4).to_bytes(2, "little")
        value[data_start:data_start] = b"\xfe\xca\x00\x00"
        eocd += 4
        value[eocd + 16 : eocd + 20] = (central_offset + 4).to_bytes(4, "little")
        with self.assertRaises(module.InventoryError):
            module.zip_members("x.zip", bytes(value))

    def test_zip_rejects_uninventoried_metadata(self):
        module = generator()
        cases = {}
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
            archive.comment = b"VALIDATED"
            archive.writestr("member.txt", b"payload")
        cases["archive_comment"] = target.getvalue()
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("member.txt")
            info.comment = b"DEPLOYMENT_QUALIFIED"
            archive.writestr(info, b"payload")
        cases["member_comment"] = target.getvalue()
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("member.txt")
            info.extra = b"\xfe\xca\x00\x00"
            archive.writestr(info, b"payload")
        cases["matching_extra"] = target.getvalue()
        for label, payload in cases.items():
            with self.subTest(metadata=label):
                with self.assertRaises(module.InventoryError):
                    module.zip_members("x.zip", payload)

    def test_zip_rejects_leading_and_trailing_bytes(self):
        module = generator()
        payload = zip_payload([("member.txt", b"payload")])
        for candidate in (b"junk" + payload, payload + b"junk"):
            with self.subTest(
                position="leading" if candidate[:4] == b"junk" else "trailing"
            ):
                with self.assertRaises(module.InventoryError):
                    module.zip_members("x.zip", candidate)

    def test_gzip_rejects_optional_header_metadata(self):
        module = generator()
        payload = bytearray(gzip_payload(b"payload"))
        payload[3] = 0x08
        payload[10:10] = b"VALIDATED\x00"
        with self.assertRaises(module.InventoryError):
            module.gzip_members("x.gz", bytes(payload))

    def test_zip_rejects_nested_archive_suffix_and_magic(self):
        module = generator()
        cases = (
            zip_payload([("nested.tgz", b"not an archive")]),
            zip_payload([("nested.txt", gzip_payload(b"payload"))]),
        )
        for payload in cases:
            with self.subTest(bytes=len(payload)):
                with self.assertRaises(module.InventoryError):
                    module.zip_members("x.zip", payload)

    def test_gzip_rejects_nested_archive_magic(self):
        module = generator()
        nested = zip_payload([("member.txt", b"payload")])
        with self.assertRaises(module.InventoryError):
            module.gzip_members("x.gz", gzip_payload(nested))

    def test_gzip_decoder_does_not_call_unbounded_flush(self):
        module = generator()
        inner = zlib.decompressobj(16 + zlib.MAX_WBITS)

        class BoundedInflater:
            def decompress(self, payload, maximum):
                return inner.decompress(payload, maximum)

            @property
            def eof(self):
                return inner.eof

            @property
            def unused_data(self):
                return inner.unused_data

            @property
            def unconsumed_tail(self):
                return inner.unconsumed_tail

            def flush(self):
                raise AssertionError("unbounded flush must not be called")

        with mock.patch.object(
            module.zlib,
            "decompressobj",
            return_value=BoundedInflater(),
        ):
            members, contents = module.gzip_members("x.gz", gzip_payload(b"payload"))
        self.assertEqual([item["name"] for item in members], ["x"])
        self.assertEqual(contents, {"x": b"payload"})

    def test_gzip_rejects_concatenated_members(self):
        module = generator()
        payload = gzip_payload(b"one") + gzip_payload(b"two")
        with self.assertRaises(module.InventoryError):
            module.gzip_members("x.log.gz", payload)

    def test_gzip_uses_natural_member_name(self):
        module = generator()
        members, contents = module.gzip_members("x.log.gz", gzip_payload(b"one"))
        self.assertEqual(members[0]["name"], "x.log")
        self.assertEqual(contents, {"x.log": b"one"})

    def test_gzip_rejects_truncation(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.gzip_members("x.gz", gzip_payload(b"hello")[:-4])

    def test_gzip_rejects_oversized_member(self):
        module = generator()
        with mock.patch.object(module, "MAX_ARCHIVE_MEMBER_BYTES", 4):
            with self.assertRaises(module.InventoryError):
                module.gzip_members("x.gz", gzip_payload(b"hello"))

    def test_gzip_rejects_ratio(self):
        module = generator()
        with mock.patch.object(module, "MAX_COMPRESSION_RATIO", 2):
            with self.assertRaises(module.InventoryError):
                module.gzip_members("x.gz", gzip_payload(b"A" * 1000))


class CliAndCandidateTests(unittest.TestCase):
    def test_command_timeout_terminates_descendant_process_group(self):
        module = generator()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "descendant-marker"
            child_source = (
                "import pathlib,time,sys;"
                "time.sleep(0.4);"
                "pathlib.Path(sys.argv[1]).write_text('alive')"
            )
            parent_source = (
                "import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                "time.sleep(5)"
            )
            with self.assertRaises(module.InventoryError):
                module.command(
                    [
                        sys.executable,
                        "-c",
                        parent_source,
                        child_source,
                        str(marker),
                    ],
                    cwd=root,
                    timeout=0.1,
                )
            time.sleep(0.6)
            self.assertFalse(marker.exists())

    def test_cli_generate_mode_has_exact_arguments(self):
        module = generator()
        freeze = "a" * 40
        arguments = module.parser().parse_args(
            [
                "generate",
                "--repo",
                ".",
                "--freeze-commit",
                freeze,
                "--captured-at-utc",
                "2026-07-23T00:00:00Z",
            ]
        )
        self.assertEqual(arguments.command, "generate")
        self.assertEqual(arguments.freeze_commit, freeze)
        self.assertEqual(arguments.captured_at_utc, "2026-07-23T00:00:00Z")
        self.assertFalse(hasattr(arguments, "implementation_commit"))

    def test_cli_verify_mode_has_exact_arguments(self):
        module = generator()
        implementation = "b" * 40
        arguments = module.parser().parse_args(
            [
                "verify",
                "--repo",
                ".",
                "--implementation-commit",
                implementation,
            ]
        )
        self.assertEqual(arguments.command, "verify")
        self.assertEqual(arguments.implementation_commit, implementation)
        self.assertFalse(hasattr(arguments, "freeze_commit"))
        self.assertFalse(hasattr(arguments, "captured_at_utc"))

    def test_cli_modes_reject_missing_required_arguments(self):
        module = generator()
        for arguments in ([], ["generate"], ["verify"]):
            with self.subTest(arguments=arguments):
                with mock.patch("sys.stderr", new=io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        module.parser().parse_args(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_cli_modes_reject_conflicting_arguments(self):
        module = generator()
        freeze = "a" * 40
        implementation = "b" * 40
        cases = (
            [
                "generate",
                "--freeze-commit",
                freeze,
                "--implementation-commit",
                implementation,
            ],
            [
                "verify",
                "--implementation-commit",
                implementation,
                "--freeze-commit",
                freeze,
            ],
            [
                "verify",
                "--implementation-commit",
                implementation,
                "--captured-at-utc",
                "2026-07-23T00:00:00Z",
            ],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with mock.patch("sys.stderr", new=io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        module.parser().parse_args(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_main_verify_mode_does_not_generate_or_write(self):
        module = generator()
        implementation = "b" * 40
        result = {"result": "PASS", "implementation_commit": implementation}
        output = io.StringIO()
        with (
            mock.patch.object(module, "verify_products", return_value=result) as verify,
            mock.patch.object(module, "generate") as generate,
            mock.patch.object(module, "write_products") as write,
            mock.patch("sys.stdout", new=output),
        ):
            return_code = module.main(
                ["verify", "--repo", ".", "--implementation-commit", implementation]
            )
        self.assertEqual(return_code, 0)
        verify.assert_called_once_with(Path("."), implementation)
        generate.assert_not_called()
        write.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), result)

    def test_registered_verifier_is_loaded_from_frozen_registry(self):
        module = generator()
        freeze = "a" * 40
        source = (
            b"TASK_ID = 'CH-T003'\n"
            b"EPOCH = 1\n"
            b"CALLS = []\n"
            b"def validate_implementation(repo, freeze_commit, implementation_commit):\n"
            b"    CALLS.append((repo, freeze_commit, implementation_commit))\n"
        )
        registry = {
            "registrations": [
                {
                    "task_id": module.TASK_ID,
                    "epoch": module.EPOCH,
                    "verifier": {
                        "path": module.FROZEN_VERIFIER_PATH,
                        "sha256": module.sha256(source),
                        "bytes": len(source),
                        "lines": len(source.splitlines()),
                    },
                }
            ]
        }
        registry_payload = module.canonical_json(registry)

        def read_file(_repo, _commit, path, **_kwargs):
            if path == module.VERIFIER_REGISTRY_PATH:
                return registry_payload
            if path == module.FROZEN_VERIFIER_PATH:
                return source
            raise AssertionError(path)

        with mock.patch.object(module, "commit_file", side_effect=read_file):
            validate, record = module.registered_product_verifier(Path("."), freeze)
        validate(Path("."), freeze, "b" * 40)
        self.assertEqual(
            validate.__globals__["CALLS"],
            [(Path("."), freeze, "b" * 40)],
        )
        self.assertEqual(record["sha256"], module.sha256(source))
        self.assertEqual(record["registry_sha256"], module.sha256(registry_payload))
        self.assertEqual(record["entrypoint"], "validate_implementation")

    def test_registered_verifier_rejects_digest_mismatch(self):
        module = generator()
        source = b"TASK_ID = 'CH-T003'\nEPOCH = 1\n"
        registry = {
            "registrations": [
                {
                    "task_id": module.TASK_ID,
                    "epoch": module.EPOCH,
                    "verifier": {
                        "path": module.FROZEN_VERIFIER_PATH,
                        "sha256": "0" * 64,
                        "bytes": len(source),
                        "lines": len(source.splitlines()),
                    },
                }
            ]
        }
        payloads = {
            module.VERIFIER_REGISTRY_PATH: module.canonical_json(registry),
            module.FROZEN_VERIFIER_PATH: source,
        }
        with (
            mock.patch.object(
                module,
                "commit_file",
                side_effect=lambda _repo, _commit, path, **_kwargs: payloads[path],
            ),
            self.assertRaises(module.InventoryError),
        ):
            module.registered_product_verifier(Path("."), "a" * 40)

    def test_registered_verifier_rejects_product_only_interface(self):
        module = generator()
        source = (
            b"TASK_ID = 'CH-T003'\n"
            b"EPOCH = 1\n"
            b"def validate_products(repo, freeze_commit, implementation_commit):\n"
            b"    return None\n"
        )
        registry = {
            "registrations": [
                {
                    "task_id": module.TASK_ID,
                    "epoch": module.EPOCH,
                    "verifier": {
                        "path": module.FROZEN_VERIFIER_PATH,
                        "sha256": module.sha256(source),
                        "bytes": len(source),
                        "lines": len(source.splitlines()),
                    },
                }
            ]
        }
        payloads = {
            module.VERIFIER_REGISTRY_PATH: module.canonical_json(registry),
            module.FROZEN_VERIFIER_PATH: source,
        }
        with (
            mock.patch.object(
                module,
                "commit_file",
                side_effect=lambda _repo, _commit, path, **_kwargs: payloads[path],
            ),
            self.assertRaises(module.InventoryError),
        ):
            module.registered_product_verifier(Path("."), "a" * 40)

    def test_verify_products_anchors_freeze_before_loading_registered_code(self):
        module = generator()
        freeze = "a" * 40
        implementation = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            with (
                mock.patch.object(
                    module, "resolve_commit", return_value=implementation
                ),
                mock.patch.object(module, "implementation_parent", return_value=freeze),
                mock.patch.object(
                    module,
                    "validate_freeze_trust_anchor",
                    side_effect=module.InventoryError("FREEZE_TRUST_ANCHOR"),
                ),
                mock.patch.object(module, "registered_product_verifier") as loader,
                self.assertRaises(module.InventoryError),
            ):
                module.verify_products(repo, implementation)
        loader.assert_not_called()

    def test_freeze_trust_anchor_binds_prior_diff_identity_and_signature(self):
        module = generator()
        freeze = "a" * 40
        allowed = b"principal ssh-ed25519 AAAA\n"
        meta = {
            "parents": module.PRIOR_LIFECYCLE["activation_commit"],
            "subject": module.EXPECTED_FREEZE_SUBJECT,
            "author_name": module.AUTHOR["name"],
            "author_email": module.AUTHOR["email"],
        }
        with (
            mock.patch.object(module, "commit_meta", return_value=meta),
            mock.patch.object(
                module, "changed_statuses", return_value=module.FREEZE_PLAN
            ),
            mock.patch.object(module, "commit_file", return_value=allowed) as read,
            mock.patch.object(
                module,
                "verify_signed_commit",
                return_value={"verified": True},
            ) as verify,
        ):
            self.assertEqual(
                module.validate_freeze_trust_anchor(Path("."), freeze),
                {"verified": True},
            )
        self.assertEqual(read.call_count, 2)
        verify.assert_called_once_with(Path("."), freeze, allowed)

    def test_git_environment_is_closed_and_drops_ambient_values(self):
        module = generator()
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                module.os.environ,
                {
                    "GIT_TRACE": "1",
                    "GIT_CONFIG_GLOBAL": "/unsafe",
                    "SENSITIVE_TOKEN": "not-retained",
                    "HOME": "/unsafe-home",
                },
                clear=True,
            ),
        ):
            environment = module.git_environment(Path(directory))
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "")
        self.assertEqual(environment["HOME"], "/nonexistent")
        self.assertNotIn("GIT_TRACE", environment)
        self.assertNotIn("SENSITIVE_TOKEN", environment)

    def test_verify_products_uses_parent_registered_verifier_and_commit_blobs(self):
        module = generator()
        freeze = "a" * 40
        implementation = "b" * 40
        calls = []

        def validate(repo, freeze_commit, implementation_commit):
            calls.append((repo, freeze_commit, implementation_commit))

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            with (
                mock.patch.object(
                    module, "resolve_commit", return_value=implementation
                ),
                mock.patch.object(module, "implementation_parent", return_value=freeze),
                mock.patch.object(module, "validate_freeze_trust_anchor") as anchor,
                mock.patch.object(
                    module,
                    "registered_product_verifier",
                    return_value=(
                        validate,
                        {
                            "path": module.FROZEN_VERIFIER_PATH,
                            "sha256": "c" * 64,
                        },
                    ),
                ),
                mock.patch.object(module, "commit_file", return_value=b"{}\n") as read,
            ):
                result = module.verify_products(repo, implementation)
        self.assertEqual(calls, [(repo.resolve(), freeze, implementation)])
        anchor.assert_called_once_with(repo.resolve(), freeze)
        self.assertEqual(read.call_count, len(module.OUTPUT_PATHS))
        self.assertEqual(
            [item["path"] for item in result["products"]],
            list(module.OUTPUT_PATHS),
        )
        self.assertFalse(result["network_used"])
        self.assertFalse(result["repository_mutated"])
        self.assertEqual(result["result"], "PASS")

    def test_python_cli_detects_main_and_argparse(self):
        module = generator()
        payload = (
            b"import argparse\n"
            b"p = argparse.ArgumentParser()\n"
            b"if __name__ == '__main__':\n"
            b"    pass\n"
        )
        value = module.python_cli_facts("tools/x.py", payload, "100644")
        self.assertEqual(value["parser"], "ARGPARSE")
        self.assertTrue(value["has_main_guard"])

    def test_python_nonentry_is_excluded(self):
        self.assertIsNone(
            generator().python_cli_facts("tools/x.py", b"VALUE = 1\n", "100644")
        )

    def test_python_syntax_error_fails(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.python_cli_facts("tools/x.py", b"if:\n", "100755")

    def test_just_recipes_are_sorted(self):
        self.assertEqual(
            generator().just_recipes(b"z:\n  true\na arg='x':\n  true\n"),
            ["a", "z"],
        )

    def test_just_duplicate_recipe_fails(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.just_recipes(b"a:\n  true\na:\n  true\n")

    def test_runtime_record_binds_streams(self):
        module = generator()
        completed = mock.Mock(returncode=2, stdout=b"", stderr=b"error\n")
        value = module.runtime_record(["tool"], completed)
        self.assertEqual(value["exit_code"], 2)
        self.assertEqual(value["stderr_sha256"], module.sha256(b"error\n"))

    def test_candidate_cycle_boundary(self):
        module = generator()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            for path in (
                module.CLAIM_LEDGER_PATH,
                module.PRODUCT_PATH,
                module.PRODUCT_TESTS_PATH,
            ):
                target = repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("candidate\n")
            value = module.candidate_implementation(
                repo, {module.CLAIM_LEDGER_PATH, "README.md"}
            )
        cyclic = [
            item
            for item in value["records"]
            if item["binding_kind"] == "NO_INNER_DIGEST"
        ]
        exact = [
            item
            for item in value["records"]
            if item["binding_kind"] == "EXACT_CANDIDATE_BYTES"
        ]
        self.assertEqual(len(cyclic), 6)
        self.assertEqual(len(exact), 3)
        self.assertTrue(all(item["sha256"] is None for item in cyclic))

    def test_candidate_snapshot_rejects_leaf_symlink(self):
        module = generator()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            for path in (
                module.CLAIM_LEDGER_PATH,
                module.PRODUCT_PATH,
                module.PRODUCT_TESTS_PATH,
            ):
                target = repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("candidate\n")
            product = repo / module.PRODUCT_PATH
            product.unlink()
            product.symlink_to(repo / module.CLAIM_LEDGER_PATH)
            with self.assertRaises(module.InventoryError):
                module.candidate_input_snapshot(repo)

    def test_binary_surface_scan_uses_best_effort_text_markers(self):
        module = generator()
        self.assertEqual(
            module.surface_types(
                "release/evidence.bin",
                b"\xffroute",
                "EXCLUDED_INTERNAL_EVIDENCE_OR_RELEASE",
            ),
            ["IPC_OR_ROUTE_SOURCE", "RELEASE_RECORD"],
        )


class ClaimsAndLanguageTests(unittest.TestCase):
    def test_claim_rows_require_52_rows(self):
        rows = generator().parse_claim_rows(claim_ledger_payload())
        self.assertEqual(len(rows), 52)

    def test_claim_rows_reject_duplicate(self):
        module = generator()
        payload = claim_ledger_payload()
        first = payload.splitlines()[0] + b"\n"
        with self.assertRaises(module.InventoryError):
            module.parse_claim_rows(payload + first)

    def test_claim_rows_preserve_inline_pipe_fragments(self):
        module = generator()
        payload = claim_ledger_payload().replace(
            b"| Statement. | PROVEN |",
            b"| Statement with | pipe. | PROVEN |",
            1,
        )
        rows = module.parse_claim_rows(payload)
        changed = next(item for item in rows if "|" in item["statement"])
        self.assertIn("|", changed["statement"])

    def test_tier_vocabulary_is_exact(self):
        module = generator()
        self.assertEqual(
            module.TIER_VOCABULARY,
            (
                "IMPLEMENTED",
                "VERIFIED",
                "VALIDATED",
                "DEPLOYMENT_QUALIFIED",
                "FIELD_VALIDATED",
                "NOT_CLAIMED",
            ),
        )

    def test_claim_type_detects_interface(self):
        self.assertEqual(
            generator().claim_type("CL-NCP-WIRE-01"),
            "INTERFACE_OR_INTEROPERABILITY",
        )

    def test_baseline_regex_uses_word_boundaries(self):
        module = generator()
        self.assertIsNotNone(module.BASELINE_PATTERN.search("This is safe."))
        self.assertIsNone(module.BASELINE_PATTERN.search("safest"))

    def test_language_scan_does_not_retain_line_text(self):
        module = generator()
        hits = module.scan_language_text(
            b"Exact CL-TEST-01 result.\n",
            pattern=module.BASELINE_PATTERN,
            scope="HANDOFF_BASELINE_TRACKED_TEXT",
            path="x.md",
            member=None,
            endpoint=None,
        )
        self.assertEqual(len(hits), 1)
        self.assertNotIn("text", hits[0])
        self.assertEqual(hits[0]["claim_ids"], ["CL-TEST-01"])

    def test_language_scan_reports_each_occurrence(self):
        module = generator()
        hits = module.scan_language_text(
            b"safe and secure\n",
            pattern=module.BASELINE_PATTERN,
            scope="HANDOFF_BASELINE_TRACKED_TEXT",
            path="x.md",
            member=None,
            endpoint=None,
        )
        self.assertEqual([item["normalized_term"] for item in hits], ["safe", "secure"])


class IpcAndSchemaTests(unittest.TestCase):
    def test_ipc_profile_has_exact_boundaries(self):
        module = generator()
        repo = Path(__file__).resolve().parents[2]
        payload = (repo / "deploy/secure-reference-v1/profile.json").read_bytes()
        value = module.capture_ipc(
            {
                "deploy/secure-reference-v1/profile.json": payload,
                "README.md": b"Engram Galadriel Prisoma",
            }
        )
        self.assertEqual(value["counts"]["profile_routes"], 17)
        self.assertEqual(value["counts"]["principals"], 8)
        self.assertEqual(value["counts"]["builder_families"], 6)
        self.assertEqual(value["counts"]["live_bound_families"], 2)
        self.assertEqual(
            value["absent_protocols"],
            ["DDS", "FFI", "GRPC", "HTTP", "MAVROS", "ROS", "SHARED_MEMORY"],
        )

    def test_ipc_profile_rejects_missing_route(self):
        module = generator()
        repo = Path(__file__).resolve().parents[2]
        profile = json.loads(
            (repo / "deploy/secure-reference-v1/profile.json").read_text()
        )
        profile["routes"].pop(next(iter(profile["routes"])))
        with self.assertRaises(module.InventoryError):
            module.capture_ipc(
                {
                    "deploy/secure-reference-v1/profile.json": json.dumps(
                        profile
                    ).encode()
                }
            )

    def test_rust_api_configuration_count_is_100(self):
        module = generator()
        packages = [{"features": {}} for _ in range(12)]
        packages.extend(
            [
                {"features": {"default": [], "real-ncp": []}},
                {"features": {"default": [], "live-zenoh": []}},
                {
                    "features": {
                        "default": [],
                        "real-ncp": [],
                        "live-zenoh": [],
                        "live-gate-dev-smoke": [],
                    }
                },
            ]
        )
        cells = sum(
            len(module.rust_api_configurations(package)) * len(module.RUST_TARGETS)
            for package in packages
        )
        self.assertEqual(cells, 100)

    def test_exported_macro_invariant_is_exact(self):
        self.assertEqual(
            set(generator().EXPECTED_EXPORTED_MACROS),
            {
                "__hc_build",
                "__hc_count",
                "__hc_encode",
                "__hc_field_ty",
                "__hc_raw_ty",
                "canonical_struct",
                "tagged_enum",
            },
        )

    def test_schema_kind_vocabulary_is_closed_in_source(self):
        source = (
            Path(__file__).with_name("current-public-surface-inventory.py").read_text()
        )
        for value in (
            "DEFINITION",
            "LIVE_EVIDENCE_INSTANCE",
            "ORDINARY_JSON_RECORD",
            "RETAINED_INSTANCE",
            "VERIFIED_VECTOR",
        ):
            self.assertIn(f'"{value}"', source)

    def test_schema_key_presence_tags_remain_lowercase(self):
        module = generator()
        repo = Path(__file__).resolve().parents[2]
        head = module.git(repo, "rev-parse", "HEAD").decode("ascii").strip()
        _object_format, _tree, entries, blobs = module.tree_snapshot(repo, head)
        records = module.inventory_records(entries, blobs)
        schemas = module.capture_schema_inventory(records, blobs)
        tags = [
            tag
            for message in schemas["canonical_messages"]
            for tag in message["key_tags"]
        ]
        self.assertTrue(tags)
        self.assertLessEqual({item["presence"] for item in tags}, {"req", "opt"})


class GithubTests(unittest.TestCase):
    def test_live_fetch_uses_private_no_proxy_tls_opener(self):
        module = generator()
        opener = mock.Mock()
        tls_context = mock.Mock()
        with (
            mock.patch.object(
                module.ssl,
                "create_default_context",
                return_value=tls_context,
            ),
            mock.patch.object(
                module.urllib.request,
                "build_opener",
                return_value=opener,
            ) as build_opener,
        ):
            module.live_github_fetch("token")
        handlers = build_opener.call_args.args
        proxy = next(
            handler
            for handler in handlers
            if isinstance(handler, module.urllib.request.ProxyHandler)
        )
        https = next(
            handler
            for handler in handlers
            if isinstance(handler, module.urllib.request.HTTPSHandler)
        )
        self.assertEqual(proxy.proxies, {})
        self.assertIs(https._context, tls_context)
        self.assertTrue(
            any(
                isinstance(handler, module.RejectGithubRedirect) for handler in handlers
            )
        )

    def test_live_fetch_redirect_handler_rejects_every_redirect(self):
        module = generator()
        handler = module.RejectGithubRedirect()
        request = mock.Mock()
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                with self.assertRaises(module.InventoryError):
                    getattr(handler, f"http_error_{code}")(
                        request,
                        None,
                        code,
                        "redirect",
                        {"Location": "https://evil.invalid/"},
                    )

    def test_live_fetch_rejects_unhandled_redirect_response(self):
        module = generator()
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 302
        response.headers = {
            "Location": "https://evil.invalid/",
        }
        response.read.return_value = b""
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(
            module.urllib.request,
            "build_opener",
            return_value=opener,
        ):
            fetch = module.live_github_fetch("token")
        with self.assertRaises(module.InventoryError):
            fetch(f"https://api.github.com/repos/{module.REPOSITORY}")
        opener.open.assert_called_once()

    def test_live_fetch_rejects_cross_boundary_paths_before_open(self):
        module = generator()
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = {}
        response.read.return_value = b"{}"
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(
            module.urllib.request,
            "build_opener",
            return_value=opener,
        ):
            fetch = module.live_github_fetch("token")
        invalid_urls = (
            f"https://api.github.com/repos/{module.REPOSITORY}-other",
            f"https://api.github.com/repos/{module.REPOSITORY}/../other",
            f"https://api.github.com/repos/{module.REPOSITORY}%2Fother",
            f"https://api.github.com/repos/{module.REPOSITORY}//hooks",
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(module.InventoryError):
                    fetch(url)
        opener.open.assert_not_called()
        status, _headers, body = fetch(
            f"https://api.github.com/repos/{module.REPOSITORY}"
        )
        self.assertEqual((status, body), (200, b"{}"))
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer token")

    def test_github_capture_is_complete_and_redacted(self):
        module = generator()
        freeze = "a" * 40
        value = module.capture_github(
            github_fetch(github_documents(freeze)),
            captured_at_utc="2026-07-23T00:00:00Z",
        )
        self.assertEqual(value["normalized"]["default_branch_head"], freeze)
        self.assertEqual(value["normalized"]["tag_count"], 0)
        self.assertEqual(value["normalized"]["release_count"], 0)
        serialized = module.canonical_json(value)
        self.assertNotIn(b"must-not-survive", serialized)
        self.assertNotIn(b"variable-value-must-not-survive", serialized)
        self.assertNotIn(b"https://secret.invalid", serialized)
        self.assertNotIn(b"ssh-ed25519 AAA", serialized)
        self.assertIn(b"SAFE_NAME", serialized)
        self.assertIn(b"SAFE_VARIABLE_NAME", serialized)
        for capture in value["captures"]:
            retained = module.canonical_json(capture["document"])
            self.assertEqual(capture["document_bytes"], len(retained))
            self.assertEqual(capture["document_sha256"], module.sha256(retained))
            endpoint_id = capture["id"].split("#", 1)[0]
            if endpoint_id in module.SENSITIVE_RAW_BODY_ENDPOINTS:
                self.assertIsNone(capture["bytes"])
                self.assertIsNone(capture["sha256"])
                self.assertIsNone(capture["etag"])
                self.assertIsNone(capture["link"])

    def test_github_sensitive_redactors_reject_wrong_top_level_shape(self):
        module = generator()
        for endpoint, document in (
            ("hooks", {"unexpected": "LEAK"}),
            ("deploy_keys", {"unexpected": "LEAK"}),
            ("autolinks", {"unexpected": "LEAK"}),
            ("variables", [{"unexpected": "LEAK"}]),
            ("secrets", [{"unexpected": "LEAK"}]),
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(module.InventoryError):
                    module.redact_github_document(endpoint, document)

    def test_github_sensitive_redactors_reject_untyped_safe_fields(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.redact_github_document(
                "variables",
                {
                    "total_count": 1,
                    "variables": [
                        {
                            "name": "NAME",
                            "value": "redacted",
                            "created_at": {"unexpected": "LEAK"},
                        }
                    ],
                },
            )
        with self.assertRaises(module.InventoryError):
            module.redact_github_document(
                "secrets",
                {
                    "total_count": 1,
                    "secrets": [
                        {
                            "name": "NAME",
                            "created_at": {"unexpected": "LEAK"},
                        }
                    ],
                },
            )

    def test_github_sensitive_404_uses_canonical_absence(self):
        module = generator()
        documents = github_documents()
        documents["variables"] = (404, {"message": "Not Found"})
        documents["secrets"] = (404, {"message": "Not Found"})
        value = module.capture_github(
            github_fetch(documents),
            captured_at_utc="2026-07-23T00:00:00Z",
        )
        captures = {
            item["id"].split("#", 1)[0]: item
            for item in value["captures"]
            if item["id"].startswith(("variables#", "secrets#"))
        }
        self.assertEqual(set(captures), {"variables", "secrets"})
        for capture in captures.values():
            self.assertIsNone(capture["document"])
            self.assertIsNone(capture["etag"])
            self.assertIsNone(capture["link"])
            self.assertIsNone(capture["bytes"])
            self.assertIsNone(capture["sha256"])

    def test_github_sensitive_values_leave_no_offline_commitment(self):
        module = generator()
        first = github_documents()
        second = github_documents()
        first["variables"][1]["variables"][0]["value"] = "alpha"
        second["variables"][1]["variables"][0]["value"] = "omega"
        first["secrets"][1]["secrets"][0]["value"] = "secret-alpha"
        second["secrets"][1]["secrets"][0]["value"] = "secret-omega"
        first_capture = module.capture_github(
            github_fetch(first, etag_suffix="-alpha"),
            captured_at_utc="2026-07-23T00:00:00Z",
        )
        second_capture = module.capture_github(
            github_fetch(second, etag_suffix="-omega"),
            captured_at_utc="2026-07-23T00:00:00Z",
        )
        self.assertEqual(
            module.canonical_json(first_capture),
            module.canonical_json(second_capture),
        )

    def test_github_sensitive_pagination_omits_validator_and_link_commitments(self):
        module = generator()
        value = module.capture_github(
            github_fetch(github_documents(), next_for="variables"),
            captured_at_utc="2026-07-23T00:00:00Z",
        )
        captures = [
            item for item in value["captures"] if item["id"].startswith("variables#")
        ]
        self.assertEqual([item["page"] for item in captures], [1, 2])
        self.assertTrue(
            all(
                item["etag"] is None
                and item["link"] is None
                and item["bytes"] is None
                and item["sha256"] is None
                for item in captures
            )
        )

    def test_github_404_is_explicitly_absent(self):
        module = generator()
        value = module.capture_github(
            github_fetch(github_documents()),
            captured_at_utc="2026-07-23T00:00:00Z",
        )
        pages = next(
            item for item in value["endpoint_summary"] if item["id"] == "pages"
        )
        self.assertIn("ABSENT", pages["disposition"])

    def test_github_rulesets_404_body_normalizes_to_absence(self):
        module = generator()
        documents = github_documents()
        documents["rulesets"] = (404, {"message": "Not Found"})
        value = module.capture_github(
            github_fetch(documents),
            captured_at_utc="2026-07-23T00:00:00Z",
        )
        self.assertEqual(value["normalized"]["rulesets"], [])

    def test_github_unexpected_permission_denial_fails(self):
        module = generator()
        documents = github_documents()
        documents["hooks"] = (403, {"message": "Forbidden"})
        with self.assertRaises(module.InventoryError):
            module.capture_github(
                github_fetch(documents),
                captured_at_utc="2026-07-23T00:00:00Z",
            )

    def test_github_evil_next_link_fails(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.capture_github(
                github_fetch(github_documents(), next_for="branches", evil_next=True),
                captured_at_utc="2026-07-23T00:00:00Z",
            )

    def test_github_same_host_cross_boundary_next_link_fails(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.capture_github(
                github_fetch(
                    github_documents(),
                    next_for="branches",
                    cross_boundary_next=True,
                ),
                captured_at_utc="2026-07-23T00:00:00Z",
            )

    def test_github_pagination_reaches_closure(self):
        module = generator()
        value = module.capture_github(
            github_fetch(github_documents(), next_for="branches"),
            captured_at_utc="2026-07-23T00:00:00Z",
        )
        summary = next(
            item for item in value["endpoint_summary"] if item["id"] == "branches"
        )
        self.assertEqual(summary["pages"], 2)
        self.assertTrue(summary["complete"])

    def test_github_tags_or_releases_fail(self):
        module = generator()
        documents = github_documents()
        documents["tags"] = (200, [{"name": "v0.1.0"}])
        with self.assertRaises(module.InventoryError):
            module.capture_github(
                github_fetch(documents),
                captured_at_utc="2026-07-23T00:00:00Z",
            )

    def test_github_body_limit_fails(self):
        module = generator()

        def fetch(_url: str):
            return 200, {}, b"x" * (module.MAX_HTTP_BODY_BYTES + 1)

        with self.assertRaises(module.InventoryError):
            module.capture_github(fetch, captured_at_utc="2026-07-23T00:00:00Z")

    def test_github_link_parser_rejects_duplicate_rel(self):
        module = generator()
        with self.assertRaises(module.InventoryError):
            module.github_links(
                '<https://api.github.com/a>; rel="next", '
                '<https://api.github.com/b>; rel="next"'
            )


class OutputAndPolicyTests(unittest.TestCase):
    def test_output_set_is_exact(self):
        module = generator()
        self.assertEqual(len(module.OUTPUT_PATHS), 6)
        self.assertEqual(
            set(module.OUTPUT_PATHS),
            set(module.IMPLEMENTATION_PLAN)
            - {
                module.CLAIM_LEDGER_PATH,
                module.PRODUCT_PATH,
                module.PRODUCT_TESTS_PATH,
            },
        )

    def test_write_products_rejects_missing_output(self):
        module = generator()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(module.InventoryError):
                module.write_products(Path(directory), {})

    def test_write_products_rejects_oversized_output_without_partial_write(self):
        module = generator()
        products = {path: {"value": "x"} for path in module.OUTPUT_PATHS}
        products[module.PUBLIC_INVENTORY_PATH] = {
            "value": "x" * module.MAX_OUTPUT_BYTES
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(module.InventoryError):
                module.write_products(root, products)
            self.assertFalse((root / module.PUBLIC_INVENTORY_PATH).exists())

    def test_write_products_creates_the_complete_exact_set(self):
        module = generator()
        products = {
            path: {"path": path, "sequence": index}
            for index, path in enumerate(module.OUTPUT_PATHS)
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            module.write_products(root, products)
            self.assertEqual(
                {path for path in module.OUTPUT_PATHS if (root / path).is_file()},
                set(module.OUTPUT_PATHS),
            )
            for path in module.OUTPUT_PATHS:
                self.assertEqual(
                    (root / path).read_bytes(),
                    module.canonical_json(products[path]),
                )

    def test_write_products_rejects_existing_target_without_changes(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / module.PUBLIC_INVENTORY_PATH
            existing.parent.mkdir(parents=True)
            existing.write_bytes(b"existing\n")
            with self.assertRaises(module.InventoryError):
                module.write_products(root, products)
            self.assertEqual(existing.read_bytes(), b"existing\n")
            self.assertFalse(
                any(
                    (root / path).exists()
                    for path in module.OUTPUT_PATHS
                    if path != module.PUBLIC_INVENTORY_PATH
                )
            )

    def test_write_products_rejects_symlink_target(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / module.PUBLIC_INVENTORY_PATH
            target.parent.mkdir(parents=True)
            target.symlink_to(root / "missing-target")
            with self.assertRaises(module.InventoryError):
                module.write_products(root, products)
            self.assertTrue(target.is_symlink())
            self.assertFalse((root / "missing-target").exists())

    def test_write_products_rejects_symlink_parent(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            (root / "audit").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(module.InventoryError):
                module.write_products(root, products)
            self.assertEqual(list(outside.iterdir()), [])

    def test_write_products_repairs_stale_empty_owned_lock(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            descriptor = os.open(
                root / module.PUBLICATION_LOCK_FILE,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)
            module.write_products(root, products)
            self.assertTrue(
                all((root / path).is_file() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_LOCK_FILE).exists())

    def test_write_products_does_not_modify_hardlinked_lock_inode(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            victim = root / "victim"
            victim.write_bytes(b"KEEP-ME\n")
            victim.chmod(0o600)
            os.link(victim, root / module.PUBLICATION_LOCK_FILE)
            with self.assertRaisesRegex(
                module.InventoryError,
                "PUBLICATION_LOCK_IDENTITY",
            ):
                module.write_products(root, products)
            self.assertEqual(victim.read_bytes(), b"KEEP-ME\n")
            self.assertEqual(
                (root / module.PUBLICATION_LOCK_FILE).read_bytes(),
                b"KEEP-ME\n",
            )

    def test_write_products_rolls_back_after_publication_error(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        original_link = module.os.link
        calls = 0

        def fail_second_link(source, target, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected publication failure")
            return original_link(source, target, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            with (
                mock.patch.object(module.os, "link", side_effect=fail_second_link),
                self.assertRaises(module.InventoryError),
            ):
                module.write_products(root, products)
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_write_products_rolls_back_after_keyboard_interrupt(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        original_link = module.os.link
        calls = 0

        def interrupt_second_link(source, target, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            return original_link(source, target, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            with (
                mock.patch.object(
                    module.os,
                    "link",
                    side_effect=interrupt_second_link,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                module.write_products(root, products)
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_write_products_revalidates_candidate_inputs_before_publication(self):
        module = generator()
        values = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            for path in (
                module.CLAIM_LEDGER_PATH,
                module.PRODUCT_PATH,
                module.PRODUCT_TESTS_PATH,
            ):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("candidate\n")
            snapshot = module.candidate_input_snapshot(root)
            products = module.GeneratedProducts(values, snapshot)
            (root / module.PRODUCT_TESTS_PATH).write_text("changed\n")
            with self.assertRaises(module.InventoryError):
                module.write_products(root, products)
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_TRANSACTION_DIRECTORY).exists())

    def test_write_products_revalidates_candidate_inputs_after_each_link(self):
        module = generator()
        values = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            for path in (
                module.CLAIM_LEDGER_PATH,
                module.PRODUCT_PATH,
                module.PRODUCT_TESTS_PATH,
            ):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("candidate\n")
            snapshot = module.candidate_input_snapshot(root)
            products = module.GeneratedProducts(values, snapshot)
            original_link = module.os.link
            linked = False

            def mutate_after_first_link(source, target, **kwargs):
                nonlocal linked
                result = original_link(source, target, **kwargs)
                if not linked:
                    linked = True
                    (root / module.PRODUCT_TESTS_PATH).write_text("changed\n")
                return result

            with (
                mock.patch.object(
                    module.os,
                    "link",
                    side_effect=mutate_after_first_link,
                ),
                self.assertRaises(module.InventoryError),
            ):
                module.write_products(root, products)
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_TRANSACTION_DIRECTORY).exists())
            self.assertFalse((root / module.PUBLICATION_LOCK_FILE).exists())

    def test_write_products_rolls_back_candidate_change_during_commit_rename(self):
        module = generator()
        values = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            for path in (
                module.CLAIM_LEDGER_PATH,
                module.PRODUCT_PATH,
                module.PRODUCT_TESTS_PATH,
            ):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("candidate\n")
            snapshot = module.candidate_input_snapshot(root)
            products = module.GeneratedProducts(values, snapshot)
            original_rename = module.os.rename
            mutated = False

            def mutate_during_commit(source, target, **kwargs):
                nonlocal mutated
                result = original_rename(source, target, **kwargs)
                if source == module.PUBLICATION_ACTIVE_MARKER and not mutated:
                    mutated = True
                    (root / module.PRODUCT_TESTS_PATH).write_text("changed\n")
                return result

            with (
                mock.patch.object(
                    module.os,
                    "rename",
                    side_effect=mutate_during_commit,
                ),
                self.assertRaises(module.InventoryError),
            ):
                module.write_products(root, products)
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_TRANSACTION_DIRECTORY).exists())
            self.assertFalse((root / module.PUBLICATION_LOCK_FILE).exists())

    def test_write_products_reports_commit_revoked_during_final_recovery(self):
        module = generator()
        values = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            for path in (
                module.CLAIM_LEDGER_PATH,
                module.PRODUCT_PATH,
                module.PRODUCT_TESTS_PATH,
            ):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("candidate\n")
            snapshot = module.candidate_input_snapshot(root)
            products = module.GeneratedProducts(values, snapshot)
            original_recovery = module.recover_product_publication
            calls = 0

            def mutate_before_final_recovery(repo, *, retain_committed=True):
                nonlocal calls
                calls += 1
                if calls == 2:
                    (root / module.PRODUCT_TESTS_PATH).write_text("changed\n")
                return original_recovery(
                    repo,
                    retain_committed=retain_committed,
                )

            with (
                mock.patch.object(
                    module,
                    "recover_product_publication",
                    side_effect=mutate_before_final_recovery,
                ),
                self.assertRaisesRegex(
                    module.InventoryError,
                    "PUBLICATION_COMMIT_REVOKED",
                ),
            ):
                module.write_products(root, products)
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_TRANSACTION_DIRECTORY).exists())
            self.assertFalse((root / module.PUBLICATION_LOCK_FILE).exists())

    def test_write_products_rolls_back_commit_marker_fsync_failure(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            original_rename = module.os.rename
            original_fsync = module.os.fsync
            commit_marker_renamed = False
            injected = False

            def observe_commit_rename(source, target, **kwargs):
                nonlocal commit_marker_renamed
                result = original_rename(source, target, **kwargs)
                if (
                    source == module.PUBLICATION_ACTIVE_MARKER
                    and target == module.PUBLICATION_COMMITTED_MARKER
                ):
                    commit_marker_renamed = True
                return result

            def fail_commit_marker_fsync(descriptor):
                nonlocal injected
                if commit_marker_renamed and not injected:
                    injected = True
                    raise OSError("injected commit-marker fsync failure")
                return original_fsync(descriptor)

            with (
                mock.patch.object(
                    module.os,
                    "rename",
                    side_effect=observe_commit_rename,
                ),
                mock.patch.object(
                    module.os,
                    "fsync",
                    side_effect=fail_commit_marker_fsync,
                ),
                self.assertRaises(module.InventoryError),
            ):
                module.write_products(root, products)
            self.assertTrue(injected)
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_TRANSACTION_DIRECTORY).exists())
            self.assertFalse((root / module.PUBLICATION_LOCK_FILE).exists())
            module.write_products(root, products)
            self.assertTrue(
                all((root / path).is_file() for path in module.OUTPUT_PATHS)
            )

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork")
    def test_write_products_recovers_after_process_termination(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            child = os.fork()
            if child == 0:
                original_link = module.os.link

                def terminate_after_link(source, target, **kwargs):
                    original_link(source, target, **kwargs)
                    os._exit(73)

                module.os.link = terminate_after_link
                module.write_products(root, products)
                os._exit(74)
            waited, status = os.waitpid(child, 0)
            self.assertEqual(waited, child)
            self.assertEqual(os.waitstatus_to_exitcode(status), 73)
            self.assertTrue((root / module.PUBLICATION_TRANSACTION_DIRECTORY).is_dir())
            self.assertEqual(
                sum((root / path).exists() for path in module.OUTPUT_PATHS),
                1,
            )
            module.write_products(root, products)
            self.assertTrue(
                all((root / path).is_file() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_TRANSACTION_DIRECTORY).exists())

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork")
    def test_write_products_recovers_partial_staged_journal(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            child = os.fork()
            if child == 0:
                original_write_all = module.write_all

                def terminate_during_journal(descriptor, payload, label):
                    if label == "PUBLICATION_JOURNAL":
                        os.write(descriptor, payload[:7])
                        os._exit(78)
                    return original_write_all(descriptor, payload, label)

                module.write_all = terminate_during_journal
                module.write_products(root, products)
                os._exit(79)
            waited, status = os.waitpid(child, 0)
            self.assertEqual(waited, child)
            self.assertEqual(os.waitstatus_to_exitcode(status), 78)
            transaction = root / module.PUBLICATION_TRANSACTION_DIRECTORY
            self.assertTrue(
                (transaction / module.PUBLICATION_JOURNAL_STAGING).is_file()
            )
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            module.write_products(root, products)
            self.assertTrue(
                all((root / path).is_file() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse(transaction.exists())

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork")
    def test_write_products_recovers_partial_staged_payload(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            child = os.fork()
            if child == 0:
                original_write_all = module.write_all

                def terminate_during_payload(descriptor, payload, label):
                    if label == "PUBLICATION_PAYLOAD":
                        os.write(descriptor, payload[:7])
                        os._exit(80)
                    return original_write_all(descriptor, payload, label)

                module.write_all = terminate_during_payload
                module.write_products(root, products)
                os._exit(81)
            waited, status = os.waitpid(child, 0)
            self.assertEqual(waited, child)
            self.assertEqual(os.waitstatus_to_exitcode(status), 80)
            transaction = root / module.PUBLICATION_TRANSACTION_DIRECTORY
            self.assertTrue((transaction / module.PUBLICATION_ACTIVE_MARKER).is_file())
            self.assertTrue((transaction / "00.pending").is_file())
            self.assertFalse(
                any((root / path).exists() for path in module.OUTPUT_PATHS)
            )
            module.write_products(root, products)
            self.assertTrue(
                all((root / path).is_file() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse(transaction.exists())

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork")
    def test_write_products_recovers_committed_transaction_idempotently(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            child = os.fork()
            if child == 0:
                original_recovery = module.recover_product_publication
                calls = 0

                def terminate_before_committed_cleanup(
                    repo,
                    *,
                    retain_committed=True,
                ):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        os._exit(75)
                    return original_recovery(
                        repo,
                        retain_committed=retain_committed,
                    )

                module.recover_product_publication = terminate_before_committed_cleanup
                module.write_products(root, products)
                os._exit(76)
            waited, status = os.waitpid(child, 0)
            self.assertEqual(waited, child)
            self.assertEqual(os.waitstatus_to_exitcode(status), 75)
            self.assertTrue(
                all((root / path).is_file() for path in module.OUTPUT_PATHS)
            )
            self.assertTrue((root / module.PUBLICATION_TRANSACTION_DIRECTORY).is_dir())
            module.write_products(root, products)
            self.assertTrue(
                all((root / path).is_file() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_TRANSACTION_DIRECTORY).exists())

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork")
    def test_write_products_rejects_concurrent_live_writer(self):
        module = generator()
        products = {path: {"path": path} for path in module.OUTPUT_PATHS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit/generated").mkdir(parents=True)
            ready_read, ready_write = os.pipe()
            resume_read, resume_write = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(ready_read)
                os.close(resume_write)
                original_link = module.os.link
                first = True

                def pause_after_first_link(source, target, **kwargs):
                    nonlocal first
                    result = original_link(source, target, **kwargs)
                    if first:
                        first = False
                        os.write(ready_write, b"1")
                        os.read(resume_read, 1)
                    return result

                module.os.link = pause_after_first_link
                module.write_products(root, products)
                os._exit(0)
            os.close(ready_write)
            os.close(resume_read)
            try:
                self.assertEqual(os.read(ready_read, 1), b"1")
                with self.assertRaisesRegex(
                    module.InventoryError,
                    "PUBLICATION_BUSY",
                ):
                    module.write_products(root, products)
                self.assertTrue(
                    (root / module.PUBLICATION_TRANSACTION_DIRECTORY).is_dir()
                )
                os.write(resume_write, b"1")
                waited, status = os.waitpid(child, 0)
                self.assertEqual(waited, child)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            finally:
                os.close(ready_read)
                os.close(resume_write)
            self.assertTrue(
                all((root / path).is_file() for path in module.OUTPUT_PATHS)
            )
            self.assertFalse((root / module.PUBLICATION_TRANSACTION_DIRECTORY).exists())
            self.assertFalse((root / module.PUBLICATION_LOCK_FILE).exists())

    def test_public_cargo_digest_binds_the_emitted_section(self):
        module = generator()
        records = [
            {
                "classification": "PUBLIC_DOCUMENTATION",
                "disposition": "SURFACE",
                "bytes": 1,
            }
            for _index in range(426)
        ]
        archives = [
            {
                "archive_type": archive_type,
                "member_count": 0,
                "expanded_bytes": 0,
            }
            for archive_type, count in (("GZIP", 30), ("ZIP", 4))
            for _index in range(count)
        ]
        toolchain = {
            "toolchain": "1.96.0",
            "tools": {},
            "cargo_public_api": {"path": "/private/tool", "version": "test"},
            "cross_compiler": {"path": "/private/zig", "version": "test"},
            "targets": [],
            "rustdoc_json_format": 57,
            "bootstrap": {},
        }
        cargo = {"metadata": {"packages": []}, "declared_mismatch": {}}
        public_api = {"observations": []}
        value = module.build_public_inventory(
            freeze_commit="a" * 40,
            freeze_tree="b" * 40,
            object_format="sha1",
            signature={},
            records=records,
            archives=archives,
            toolchain=toolchain,
            cargo=cargo,
            public_api=public_api,
            cli={},
            ipc={},
            schemas={},
            documentation={},
            candidate={
                "records": [{} for _index in range(9)],
                "expected_implementation_regular_blobs": 434,
            },
        )
        self.assertEqual(
            value["digests"]["cargo_sha256"],
            module.sha256(module.canonical_json(value["cargo"])),
        )
        self.assertNotEqual(
            value["digests"]["cargo_sha256"],
            module.sha256(module.canonical_json(cargo)),
        )

    def test_review_boundary_literals_exist(self):
        source = (
            Path(__file__).with_name("current-public-surface-inventory.py").read_text()
        )
        self.assertIn('"review_completed_at_i": False', source)
        self.assertIn('"review_required_at_c": True', source)
        self.assertIn('"review_status": "C_REVIEW_REQUIRED"', source)

    def test_rust_policy_has_all_pinned_tokens(self):
        source = (
            Path(__file__).with_name("current-public-surface-inventory.py").read_text()
        )
        for token in (
            "0.52.0",
            "0.16.0",
            "1.96.0",
            "acdc7b1733d52476fc2ce456a2a0292b82c367566fe0d2ab15c12b99974c8d24",
            "71cc3995a7586753ebf82c66dfb8bef43df446517550678781834586a960f8c9",
            "CRATE_CC_NO_DEFAULTS",
            "RUSTC_BOOTSTRAP",
            "CARGO_NET_OFFLINE",
            "--document-hidden-items",
            "--locked",
            "--offline",
        ):
            self.assertIn(token, source)

    def test_no_environment_secret_name_is_serialized_by_policy(self):
        module = generator()
        policy = {
            "authentication": "BEARER_TOKEN_USED_NOT_RETAINED",
            "headers": [module.GITHUB_ACCEPT, module.GITHUB_API_VERSION],
        }
        text = module.canonical_json(policy)
        self.assertNotIn(b"Authorization:", text)

    def test_utc_validation_is_strict(self):
        module = generator()
        self.assertEqual(
            module.validate_utc("2026-07-23T00:00:00Z"),
            "2026-07-23T00:00:00Z",
        )
        with self.assertRaises(module.InventoryError):
            module.validate_utc("2026-07-23 00:00:00")


if __name__ == "__main__":
    unittest.main()
