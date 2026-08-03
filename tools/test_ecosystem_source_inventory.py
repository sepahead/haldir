#!/usr/bin/env python3
"""Adversarial tests for the privacy-safe ecosystem source inventory."""

from __future__ import annotations

import contextlib
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import xml.etree.ElementTree as ET


MODULE_PATH = Path(__file__).with_name("ecosystem_source_inventory.py")
SPEC = importlib.util.spec_from_file_location("ecosystem_source_inventory", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import bootstrap guard
    raise RuntimeError("cannot load ecosystem source inventory")
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


OWNER = {
    "account_id": 10_104_569,
    "login": "sepahead",
    "node_id": "MDQ6VXNlcjEwMTA0NTY5",
}
RATE = {
    "attempts": 1,
    "remaining": 4_999,
    "reset_at_utc": "2030-01-02T03:04:05Z",
}
PUBLIC_ENDPOINT = inventory.PUBLIC_ENDPOINT_TEMPLATE.format(owner="sepahead", page=1)
OWNER_ENDPOINT = inventory.OWNER_ENDPOINT_TEMPLATE.format(page=1)
PRIVATE_CANARY = "sepahead/private-canary-never-publish-7f34a9"


def identity_payload(*, login: str = "sepahead", account_id: int = 10_104_569):
    return {
        "id": account_id,
        "login": login,
        "node_id": OWNER["node_id"],
        "type": "User",
    }


def rest_repository(
    repository: str,
    repository_id: int,
    *,
    visibility: str = "public",
    fork: bool = False,
    default_branch: str | None = "main",
    language: str | None = "Rust",
) -> dict[str, object]:
    return {
        "archived": False,
        "default_branch": default_branch,
        "fork": fork,
        "full_name": repository,
        "html_url": f"https://github.com/{repository}",
        "id": repository_id,
        "language": language,
        "license": {"spdx_id": "MIT"},
        "owner": identity_payload(),
        "private": visibility == "private",
        "pushed_at": "2026-08-01T10:11:12Z",
        "updated_at": "2026-08-01T10:11:13Z",
        "visibility": visibility,
    }


def ref_endpoint(repository: str, branch: str = "main") -> str:
    return f"/repos/{repository}/git/ref/heads/{branch}"


def ref_payload(branch: str, oid: str) -> dict[str, object]:
    return {
        "node_id": "fixture-ref-node",
        "object": {"sha": oid, "type": "commit", "url": "https://api.github.test"},
        "ref": f"refs/heads/{branch}",
        "url": "https://api.github.test",
    }


def oid(repository_id: int, suffix: str = "") -> str:
    base = f"{repository_id:040x}"
    if suffix:
        return base[: -len(suffix)] + suffix
    return base


class FakeRestClient:
    """One strict endpoint queue; unexpected or excess requests fail the test."""

    identity = {
        "bytes": 42,
        "name": "gh",
        "sha256": "a" * 64,
        "version": "gh version 2.80.0 (fixture)",
    }
    head_workers = 1
    timeout_seconds = 60
    credential_binding = dict(inventory.CREDENTIAL_BINDING)
    environment_binding = dict(inventory.GH_ENVIRONMENT_BINDING)
    executable_binding = {
        "bytes": 42,
        "method": inventory.EXECUTABLE_BINDING_METHOD,
        "mode": "0500",
        "sha256": "a" * 64,
    }

    def __init__(self) -> None:
        self.responses: dict[str, list[tuple[object, dict[str, object]]]] = {}
        self.calls: list[str] = []
        self.pin_verifications = 0

    def queue(
        self,
        endpoint: str,
        *values: object,
        rate: dict[str, object] | None = None,
    ) -> None:
        selected_rate = RATE if rate is None else rate
        queue = self.responses.setdefault(endpoint, [])
        queue.extend(
            (copy.deepcopy(value), copy.deepcopy(selected_rate)) for value in values
        )

    def get(self, endpoint: str, *, allow_empty_repository: bool = False):
        del allow_empty_repository
        self.calls.append(endpoint)
        if endpoint not in self.responses or not self.responses[endpoint]:
            raise AssertionError(f"unexpected fixture endpoint: {endpoint}")
        return self.responses[endpoint].pop(0)

    def assert_consumed(self) -> None:
        remaining = {key: len(value) for key, value in self.responses.items() if value}
        if remaining:
            raise AssertionError(f"unconsumed fixture responses: {remaining}")

    def verify_pins(self) -> None:
        self.pin_verifications += 1


def queue_repository_heads(
    client: FakeRestClient,
    record: dict[str, object],
    *,
    repetitions: int,
    exact_oid: str | None = None,
) -> None:
    repository = str(record["full_name"])
    default_branch = record["default_branch"]
    if default_branch is None:
        return
    observed_oid = exact_oid or oid(int(record["id"]))
    client.queue(
        ref_endpoint(repository, str(default_branch)),
        *([ref_payload(str(default_branch), observed_oid)] * repetitions),
    )


def queue_complete_capture(
    client: FakeRestClient,
    public_record: dict[str, object],
    private_record: dict[str, object],
) -> None:
    client.queue(f"/users/{OWNER['login']}", identity_payload(), identity_payload())
    client.queue("/user", identity_payload(), identity_payload())
    client.queue(PUBLIC_ENDPOINT, [public_record], [public_record])
    client.queue(
        OWNER_ENDPOINT,
        [public_record, private_record],
        [public_record, private_record],
    )
    queue_repository_heads(client, public_record, repetitions=4)
    queue_repository_heads(client, private_record, repetitions=2)


def resolved_decisions(
    records: list[dict[str, object]],
    *,
    justification: str = "Explicit source-bound review decision.",
    heads_sha256: str | None = None,
) -> dict[str, object]:
    return {
        "classification_review_basis": inventory.CLASSIFICATION_REVIEW_BASIS,
        "owner": {
            "account_id": records[0]["owner_id"],
            "login": records[0]["owner"],
        },
        "records": [
            {
                "agentic_tool_relevance": False,
                "audit_depth": "INVENTORY_ONLY",
                "classification_status": inventory.CLASSIFICATION_STATUS,
                "controller_relevance": False,
                "evidence_relevance": False,
                "first_party": True,
                "justification": justification,
                "plant_relevance": False,
                "repository": record["repository"],
                "repository_id": record["repository_id"],
                "review_date": inventory.MAINTAINED_REVIEW_DATE,
                "review_attestation": inventory.REVIEW_ATTESTATION,
                "review_status": inventory.REVIEW_STATUS,
                "reviewer": "fixture-reviewer",
                "state_relevance": False,
                "supply_chain_relevance": False,
                "tcb_class": "OFFLINE_RESEARCH_TOOL",
                "transport_relevance": False,
            }
            for record in records
        ],
        "repository_heads_sha256": (
            heads_sha256
            if heads_sha256 is not None
            else inventory.sha256(inventory.canonical_jsonl(records))
        ),
        "schema_id": inventory.DECISIONS_SCHEMA,
        "schema_version": inventory.SCHEMA_VERSION,
    }


def valid_supersession() -> dict[str, object]:
    value = json.loads(
        (
            MODULE_PATH.parent.parent / "evidence/source-review/supersession-audit.json"
        ).read_text(encoding="utf-8")
    )
    inventory.validate_supersession_audit(value)
    return value


def pid_is_gone(process_id: int, *, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.05)
    return False


def process_test_client(*, timeout_seconds: int = 1):
    client = object.__new__(inventory.GhClient)
    client.executable = Path(sys.executable).resolve()
    client.timeout_seconds = timeout_seconds
    client._active_processes = set()
    client._process_lock = threading.RLock()
    client._guarded_signals = frozenset()
    client._environment = {
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    client._verify_api_config_directory = lambda: None
    client._verify_executable_directory = lambda: None
    client._open_verified_executable = lambda: os.open(client.executable, os.O_RDONLY)
    return client


class EcosystemSourceInventoryTests(unittest.TestCase):
    maxDiff = None

    def assert_inventory_error(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(inventory.InventoryError) as raised:
            callable_(*args, **kwargs)
        self.assertEqual(str(raised.exception), code)

    def capture_fixture(self, root: Path) -> dict[str, object]:
        public_record = rest_repository(
            "sepahead/alpha-public", 1_001, fork=True, language="Rust"
        )
        private_record = rest_repository(
            PRIVATE_CANARY, 9_001, visibility="private", language="Python"
        )
        client = FakeRestClient()
        queue_complete_capture(client, public_record, private_record)
        paths = {
            "root": root,
            "public_heads": root / "repository-heads.jsonl",
            "owner_visible": root / "owner-visible-repositories.private.jsonl",
            "capture_metadata": root / "capture-metadata.json",
            "command_log": root / "command-log.jsonl",
            "private_telemetry": root / inventory.PRIVATE_TELEMETRY_BASENAME,
            "public_decisions": root / "repository-classification-decisions.json",
            "private_decisions": root
            / "repository-classification-decisions.private.json",
            "supersession_audit": root / "supersession-audit.json",
        }
        fixture_instant = (
            f"{inventory.MAINTAINED_REVIEW_DATE}T12:00:00.000000Z"
        )
        with mock.patch.object(inventory, "utc_now", return_value=fixture_instant):
            result = inventory.capture_files(
                client=client,
                owner_name="sepahead",
                public_heads=paths["public_heads"],
                owner_visible=paths["owner_visible"],
                capture_metadata=paths["capture_metadata"],
                command_log=paths["command_log"],
                private_telemetry=paths["private_telemetry"],
                minimum_remaining=100,
                maximum_pages=10,
                expected_public_repositories=1,
                expected_private_repositories=1,
                _test_profile=True,
            )
        self.assertEqual(result, {"owner_visible": 2, "private": 1, "public": 1})
        self.assertEqual(client.pin_verifications, 1)
        client.assert_consumed()
        public_raw, _public_payload = inventory._load_jsonl(paths["public_heads"])
        owner_raw, owner_payload = inventory._load_jsonl(paths["owner_visible"])
        private_raw = [
            record for record in owner_raw if record["visibility"] == "PRIVATE"
        ]
        inventory._atomic_write(
            paths["public_decisions"],
            inventory.canonical_json(resolved_decisions(public_raw)),
            private=False,
        )
        inventory._atomic_write(
            paths["private_decisions"],
            inventory.canonical_json(
                resolved_decisions(
                    private_raw, heads_sha256=inventory.sha256(owner_payload)
                )
            ),
            private=True,
        )
        inventory._atomic_write(
            paths["supersession_audit"],
            inventory.canonical_json(valid_supersession()),
            private=False,
        )
        (root / ".gitignore").write_text(
            "*.private.json\n*.private.jsonl\n*.private.csv\n",
            encoding="utf-8",
        )
        subprocess.run(
            ("git", "init", "--quiet", str(root)),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ("git", "-C", str(root), "add", "--all"),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        inventory.render_files(
            public_heads=paths["public_heads"],
            owner_visible=paths["owner_visible"],
            public_decisions=paths["public_decisions"],
            private_decisions=paths["private_decisions"],
            capture_metadata=paths["capture_metadata"],
            command_log=paths["command_log"],
            output_root=root,
            supersession_audit=paths["supersession_audit"],
            _test_profile=True,
        )
        subprocess.run(
            ("git", "-C", str(root), "add", "--all"),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        sealed = inventory.seal_files(
            public_heads=paths["public_heads"],
            owner_visible=paths["owner_visible"],
            public_decisions=paths["public_decisions"],
            private_decisions=paths["private_decisions"],
            capture_metadata=paths["capture_metadata"],
            command_log=paths["command_log"],
            output_root=root,
            supersession_audit=paths["supersession_audit"],
            _test_profile=True,
        )
        self.assertEqual(sealed["seal_state"], "AUDIT_UNSTAGED_READY")
        subprocess.run(
            (
                "git",
                "-C",
                str(root),
                "add",
                "--",
                inventory.AUDIT_METADATA_BASENAME,
            ),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return paths

    def closure_kwargs(
        self, paths: dict[str, object], *, audit_payload: bytes | None = None
    ) -> dict[str, object]:
        root = paths["root"]
        assert isinstance(root, Path)
        public_records, public_payload = inventory._load_jsonl(paths["public_heads"])
        owner_records, _owner_payload = inventory._load_jsonl(
            paths["owner_visible"], private=True
        )
        private_records = [
            record for record in owner_records if record["visibility"] == "PRIVATE"
        ]
        required: dict[Path, bytes] = {}
        for key in (
            "public_heads",
            "capture_metadata",
            "command_log",
            "public_decisions",
            "supersession_audit",
        ):
            path = paths[key]
            assert isinstance(path, Path)
            required[path] = path.read_bytes()
        required[root / inventory.PUBLIC_CLASSIFICATION_JSON_BASENAME] = (
            root / inventory.PUBLIC_CLASSIFICATION_JSON_BASENAME
        ).read_bytes()
        required[root / inventory.PUBLIC_CLASSIFICATION_CSV_BASENAME] = (
            root / inventory.PUBLIC_CLASSIFICATION_CSV_BASENAME
        ).read_bytes()
        del public_payload
        return {
            "evidence_root": root,
            "expected_private_payloads": {
                paths["owner_visible"]: paths["owner_visible"].read_bytes(),
                paths["private_decisions"]: paths["private_decisions"].read_bytes(),
                root / inventory.PRIVATE_LEDGER_BASENAME: (
                    root / inventory.PRIVATE_LEDGER_BASENAME
                ).read_bytes(),
                paths["private_telemetry"]: paths["private_telemetry"].read_bytes(),
            },
            "private_records": private_records,
            "public_records": public_records,
            "audit_path": root / inventory.AUDIT_METADATA_BASENAME,
            "required_staged_payloads": required,
            "audit_payload": audit_payload,
        }

    def test_canonical_json_and_jsonl_are_deterministic(self) -> None:
        self.assertEqual(
            inventory.canonical_json({"z": 1, "a": "é"}),
            b'{\n  "a": "\xc3\xa9",\n  "z": 1\n}\n',
        )
        self.assertEqual(
            inventory.canonical_jsonl([{"z": 1, "a": 2}, {"x": False}]),
            b'{"a":2,"z":1}\n{"x":false}\n',
        )

    def test_noncanonical_json_and_jsonl_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bad_json = root / "bad.json"
            bad_json.write_bytes(b'{"z":1,"a":2}\n')
            self.assert_inventory_error(
                "JSON_NOT_CANONICAL", inventory._load_json, bad_json
            )
            bad_jsonl = root / "bad.jsonl"
            bad_jsonl.write_bytes(b'{"z":1, "a":2}\n')
            self.assert_inventory_error(
                "JSONL_NOT_CANONICAL", inventory._load_jsonl, bad_jsonl
            )

    def test_gh_adapter_uses_explicit_get_and_parses_rate_headers(self) -> None:
        client = object.__new__(inventory.GhClient)
        observed: list[tuple[str, ...]] = []

        def fake_run(arguments, *, stdout_limit, allowed_return_codes):
            self.assertEqual(stdout_limit, inventory.MAX_API_RESPONSE_BYTES)
            self.assertEqual(allowed_return_codes, frozenset({0, 1}))
            observed.append(tuple(arguments))
            return (
                (
                    b"HTTP/2.0 200 OK\r\n"
                    b"X-RateLimit-Remaining: 4998\r\n"
                    b"X-RateLimit-Reset: 1893452645\r\n\r\n"
                    b'{"ok":true}'
                ),
                0,
            )

        client._run = fake_run
        value, rate = client.get("/user")
        self.assertEqual(value, {"ok": True})
        self.assertEqual(rate["remaining"], 4_998)
        self.assertIn(("--method", "GET"), list(zip(observed[0], observed[0][1:])))
        self.assertNotIn("POST", observed[0])

    def test_production_tool_resolution_uses_only_sanitized_path_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsafe = root / "unsafe"
            safe = root / "safe"
            unsafe.mkdir(mode=0o700)
            safe.mkdir(mode=0o700)
            (unsafe / "gh").write_bytes(b"unsafe")
            (safe / "gh").write_bytes(b"safe")
            (unsafe / "gh").chmod(0o500)
            (safe / "gh").chmod(0o500)
            unsafe.chmod(0o777)
            with mock.patch.dict(
                os.environ,
                {"PATH": f"relative{os.pathsep}{unsafe}{os.pathsep}{safe}"},
                clear=False,
            ):
                sanitized = inventory._sanitized_search_path()
                self.assertNotIn(str(unsafe), sanitized.split(os.pathsep))
                self.assertEqual(
                    inventory._resolve_safe_executable("gh", sanitized_path=sanitized),
                    (safe / "gh").resolve(),
                )
                (safe / "gh").chmod(0o520)
                self.assert_inventory_error(
                    "TOOL_EXECUTABLE",
                    inventory._resolve_safe_executable,
                    "gh",
                    sanitized_path=sanitized,
                )

    def test_gh_adapter_accepts_only_the_exact_empty_repository_409(self) -> None:
        client = object.__new__(inventory.GhClient)

        def empty_run(arguments, *, stdout_limit, allowed_return_codes):
            del arguments, stdout_limit
            self.assertEqual(allowed_return_codes, frozenset({0, 1}))
            return (
                (
                    b"HTTP/2.0 409 Conflict\r\n"
                    b"X-RateLimit-Remaining: 4998\r\n"
                    b"X-RateLimit-Reset: 1893452645\r\n\r\n"
                    b'{"message":"Git Repository is empty."}'
                ),
                1,
            )

        client._run = empty_run
        value, _rate = client.get(
            "/repos/sepahead/empty/git/ref/heads/main",
            allow_empty_repository=True,
        )
        self.assertIsNone(value)

        def conflict_run(arguments, *, stdout_limit, allowed_return_codes):
            del arguments, stdout_limit, allowed_return_codes
            return (
                (
                    b"HTTP/2.0 409 Conflict\r\n"
                    b"X-RateLimit-Remaining: 4998\r\n"
                    b"X-RateLimit-Reset: 1893452645\r\n\r\n"
                    b'{"message":"Different conflict."}'
                ),
                1,
            )

        client._run = conflict_run
        self.assert_inventory_error(
            "GH_HTTP_STATUS",
            client.get,
            "/repos/sepahead/empty/git/ref/heads/main",
            allow_empty_repository=True,
        )

    def test_gh_adapter_retries_only_a_headerless_transport_failure(self) -> None:
        client = object.__new__(inventory.GhClient)
        attempts = 0

        def retry_run(arguments, *, stdout_limit, allowed_return_codes):
            nonlocal attempts
            del arguments, stdout_limit, allowed_return_codes
            attempts += 1
            if attempts == 1:
                return b"", 1
            return (
                (
                    b"HTTP/2.0 200 OK\r\n"
                    b"X-RateLimit-Remaining: 4998\r\n"
                    b"X-RateLimit-Reset: 1893452645\r\n\r\n"
                    b'{"ok":true}'
                ),
                0,
            )

        client._run = retry_run
        with mock.patch.object(inventory.time, "sleep") as sleep:
            value, rate = client.get("/user")
        self.assertEqual(value, {"ok": True})
        self.assertEqual(rate["attempts"], 2)
        sleep.assert_called_once_with(0.25)

    def test_gh_adapter_pins_one_credential_and_one_executable_copy(self) -> None:
        token_canary = "ghp_test-token-never-record-4f8d2"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "fake-gh"
            log = root / "calls.jsonl"
            script = f"""#!{Path(sys.executable).resolve()}
import json
import os
import sys

token = {token_canary!r}
operation = "version" if sys.argv[1:] == ["--version"] else "auth" if sys.argv[1:3] == ["auth", "token"] else "api"
record = {{
    "competing_tokens_absent": all(name not in os.environ for name in ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GITHUB_TOKEN")),
    "debug_and_force_tty_absent": all(name not in os.environ for name in ("DEBUG", "GH_DEBUG", "GH_FORCE_TTY")),
    "gh_token_matches": os.environ.get("GH_TOKEN") == token,
    "operation": operation,
    "telemetry_disabled": os.environ.get("GH_TELEMETRY") == "0" and os.environ.get("DO_NOT_TRACK") == "1",
    "update_notifiers_disabled": os.environ.get("GH_NO_UPDATE_NOTIFIER") == "1" and os.environ.get("GH_NO_EXTENSION_UPDATE_NOTIFIER") == "1",
}}
with open({str(log)!r}, "a", encoding="utf-8") as output:
    output.write(json.dumps(record, sort_keys=True) + "\\n")
if operation == "version":
    print("gh version 2.80.0 (fake)")
elif operation == "auth":
    print(token)
else:
    sys.stdout.write("HTTP/2.0 200 OK\\r\\nX-RateLimit-Remaining: 4998\\r\\nX-RateLimit-Reset: 1893452645\\r\\n\\r\\n{{\\\"ok\\\":true}}")
"""
            executable.write_text(script, encoding="utf-8")
            executable.chmod(0o500)
            environment = {
                **os.environ,
                "GH_ENTERPRISE_TOKEN": "competing-one",
                "GH_TOKEN": "competing-two",
                "GITHUB_ENTERPRISE_TOKEN": "competing-three",
                "GITHUB_TOKEN": "competing-four",
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                client = inventory.GhClient(
                    _test_executable=str(executable),
                    timeout_seconds=5,
                    head_workers=1,
                )
            try:
                pinned_sha = client.executable_binding["sha256"]
                executable.chmod(0o700)
                executable.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
                executable.chmod(0o500)
                value, _rate = client.get("/user")
                self.assertEqual(value, {"ok": True})
                client.verify_pins()
                self.assertEqual(client.executable_binding["sha256"], pinned_sha)
                retained = {
                    "credential": client.credential_binding,
                    "executable": client.executable_binding,
                    "identity": client.identity,
                }
                retained_payload = inventory.canonical_json(retained)
                self.assertNotIn(token_canary.encode("ascii"), retained_payload)
                self.assertNotIn(
                    inventory.sha256(token_canary.encode("ascii")).encode("ascii"),
                    retained_payload,
                )
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual(
                    [item["operation"] for item in calls], ["version", "auth", "api"]
                )
                self.assertFalse(calls[0]["gh_token_matches"])
                self.assertFalse(calls[1]["gh_token_matches"])
                self.assertTrue(calls[2]["gh_token_matches"])
                self.assertTrue(all(item["competing_tokens_absent"] for item in calls))
                self.assertTrue(
                    all(item["debug_and_force_tty_absent"] for item in calls)
                )
                self.assertTrue(all(item["telemetry_disabled"] for item in calls))
                self.assertTrue(
                    all(item["update_notifiers_disabled"] for item in calls)
                )
                self.assertNotIn(token_canary, log.read_text())
            finally:
                client.close()

    def test_gh_adapter_detects_retained_copy_tampering_and_hardlinks(self) -> None:
        token_canary = "ghp_test-copy-pin-1a2b3"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "fake-gh"
            executable.write_text(
                f"#!{Path(sys.executable).resolve()}\n"
                "import sys\n"
                f"token={token_canary!r}\n"
                "print('gh version 2.80.0 (fake)' if sys.argv[1:] == ['--version'] else token)\n",
                encoding="utf-8",
            )
            executable.chmod(0o500)
            client = inventory.GhClient(
                _test_executable=str(executable), timeout_seconds=5
            )
            try:
                hardlink = root / "copy-hardlink"
                os.link(client.executable, hardlink)
                self.assert_inventory_error("GH_EXECUTABLE_PIN", client.verify_pins)
            finally:
                client.close()

    def test_gh_exec_boundary_rejects_a_path_swap(self) -> None:
        token_canary = "ghp_test-exec-boundary-9c8d7"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "fake-gh"
            executable.write_text(
                f"#!{Path(sys.executable).resolve()}\n"
                "import sys\n"
                f"token={token_canary!r}\n"
                "if sys.argv[1:] == ['--version']:\n"
                " print('gh version 2.80.0 (fake)')\n"
                "elif sys.argv[1:3] == ['auth','token']:\n"
                " print(token)\n"
                "else:\n"
                " sys.stdout.write('HTTP/2.0 200 OK\\r\\nX-RateLimit-Remaining: 4998\\r\\nX-RateLimit-Reset: 1893452645\\r\\n\\r\\n{\"ok\":true}')\n",
                encoding="utf-8",
            )
            executable.chmod(0o500)
            client = inventory.GhClient(
                _test_executable=str(executable), timeout_seconds=5
            )
            saved = client._executable_directory / "gh.saved"
            alternate = root / "alternate-gh"
            alternate.write_text("#!/bin/sh\nexit 77\n", encoding="utf-8")
            alternate.chmod(0o500)
            real_open = client._open_verified_executable

            def open_then_swap() -> int:
                descriptor = real_open()
                client._executable_directory.chmod(0o700)
                client.executable.rename(saved)
                alternate.rename(client.executable)
                client._executable_directory.chmod(0o500)
                return descriptor

            try:
                with mock.patch.object(
                    client,
                    "_open_verified_executable",
                    side_effect=open_then_swap,
                ):
                    self.assert_inventory_error(
                        "GH_EXECUTABLE_PIN", client.get, "/user"
                    )
            finally:
                client._executable_directory.chmod(0o700)
                if client.executable.exists():
                    client.executable.unlink()
                if saved.exists():
                    saved.rename(client.executable)
                client._executable_directory.chmod(0o500)
                client.close()

    def test_gh_exec_boundary_rejects_swap_execute_restore(self) -> None:
        token_canary = "ghp_test-exec-restore-4d3c2"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "fake-gh"
            executable.write_text(
                f"#!{Path(sys.executable).resolve()}\n"
                "import sys\n"
                f"token={token_canary!r}\n"
                "if sys.argv[1:] == ['--version']:\n"
                " print('gh version 2.80.0 (fake)')\n"
                "elif sys.argv[1:3] == ['auth','token']:\n"
                " print(token)\n"
                "else:\n"
                " sys.stdout.write('HTTP/2.0 200 OK\\r\\nX-RateLimit-Remaining: 4998\\r\\nX-RateLimit-Reset: 1893452645\\r\\n\\r\\n{\"ok\":true}')\n",
                encoding="utf-8",
            )
            executable.chmod(0o500)
            client = inventory.GhClient(
                _test_executable=str(executable), timeout_seconds=5
            )
            saved = client._executable_directory / "gh.saved"
            alternate = root / "alternate-native"
            alternate.write_bytes(Path("/bin/echo").read_bytes())
            alternate.chmod(0o500)
            real_open = client._open_verified_executable
            real_popen = inventory.subprocess.Popen

            def open_then_swap() -> int:
                descriptor = real_open()
                client._executable_directory.chmod(0o700)
                client.executable.rename(saved)
                alternate.rename(client.executable)
                client._executable_directory.chmod(0o500)
                return descriptor

            def execute_then_restore(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                client._executable_directory.chmod(0o700)
                client.executable.unlink()
                saved.rename(client.executable)
                client._executable_directory.chmod(0o500)
                return process

            try:
                with (
                    mock.patch.object(
                        client,
                        "_open_verified_executable",
                        side_effect=open_then_swap,
                    ),
                    mock.patch.object(
                        inventory.subprocess,
                        "Popen",
                        side_effect=execute_then_restore,
                    ),
                ):
                    self.assert_inventory_error(
                        "GH_EXECUTABLE_PIN", client.get, "/user"
                    )
            finally:
                client.close()

    def test_gh_signal_guard_rejects_overlapping_clients(self) -> None:
        guarded = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGHUP"):
            guarded.append(signal.SIGHUP)
        originals = {signum: signal.getsignal(signum) for signum in guarded}

        def bare_client():
            client = object.__new__(inventory.GhClient)
            client._active_processes = set()
            client._process_lock = threading.RLock()
            client._previous_signal_handlers = {}
            client._signal_handler_callback = None
            return client

        first = bare_client()
        second = bare_client()
        first._install_signal_guards()
        try:
            self.assert_inventory_error(
                "GH_SIGNAL_GUARD", second._install_signal_guards
            )
            for signum in guarded:
                self.assertEqual(
                    signal.getsignal(signum), first._signal_handler_callback
                )
        finally:
            first._restore_signal_guards()
        for signum, handler in originals.items():
            self.assertEqual(signal.getsignal(signum), handler)

    def test_run_kills_process_group_on_timeout_and_exited_leader(self) -> None:
        cases = {
            "sleeping-leader": "time.sleep(60)",
            "exited-leader": "raise SystemExit(0)",
        }
        for case, ending in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                pid_file = Path(temporary) / "pids"
                code = (
                    "import os,subprocess,sys,time\n"
                    "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                    f"open({str(pid_file)!r},'w').write(str(os.getpid())+' '+str(child.pid))\n"
                    f"{ending}\n"
                )
                client = process_test_client(timeout_seconds=1)
                started = time.monotonic()
                self.assert_inventory_error(
                    "GH_TIMEOUT",
                    client._run,
                    ("-c", code),
                    stdout_limit=128,
                )
                self.assertLess(time.monotonic() - started, 4)
                direct_pid, child_pid = map(int, pid_file.read_text().split())
                self.assertTrue(pid_is_gone(direct_pid))
                self.assertTrue(pid_is_gone(child_pid))

    def test_run_kills_process_group_on_output_bounds(self) -> None:
        for stream, code_expected in (
            ("stdout", "GH_OUTPUT_BOUND"),
            ("stderr", "GH_STDERR_BOUND"),
        ):
            with (
                self.subTest(stream=stream),
                tempfile.TemporaryDirectory() as temporary,
            ):
                pid_file = Path(temporary) / "pids"
                file_descriptor = 1 if stream == "stdout" else 2
                payload = b"x" * 65
                code = (
                    "import os,subprocess,sys,time\n"
                    "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                    f"open({str(pid_file)!r},'w').write(str(os.getpid())+' '+str(child.pid))\n"
                    f"os.write({file_descriptor},{payload!r})\n"
                    "time.sleep(60)\n"
                )
                client = process_test_client(timeout_seconds=5)
                patcher = (
                    mock.patch.object(inventory, "MAX_API_STDERR_BYTES", 64)
                    if stream == "stderr"
                    else contextlib.nullcontext()
                )
                with patcher:
                    self.assert_inventory_error(
                        code_expected,
                        client._run,
                        ("-c", code),
                        stdout_limit=64,
                    )
                direct_pid, child_pid = map(int, pid_file.read_text().split())
                self.assertTrue(pid_is_gone(direct_pid))
                self.assertTrue(pid_is_gone(child_pid))

    @unittest.skipUnless(hasattr(signal, "setitimer"), "POSIX interval timer required")
    def test_run_kills_process_group_before_propagating_keyboard_interrupt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "pids"
            code = (
                "import os,subprocess,sys,time\n"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                f"open({str(pid_file)!r},'w').write(str(os.getpid())+' '+str(child.pid))\n"
                "time.sleep(60)\n"
            )
            client = process_test_client(timeout_seconds=5)
            previous = signal.getsignal(signal.SIGALRM)

            def interrupt(_signum, _frame):
                raise KeyboardInterrupt

            signal.signal(signal.SIGALRM, interrupt)
            signal.setitimer(signal.ITIMER_REAL, 0.25)
            try:
                with self.assertRaises(KeyboardInterrupt):
                    client._run(("-c", code), stdout_limit=128)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
            direct_pid, child_pid = map(int, pid_file.read_text().split())
            self.assertTrue(pid_is_gone(direct_pid))
            self.assertTrue(pid_is_gone(child_pid))

    def test_run_signal_guard_kills_process_group_on_sigterm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "pids"
            workload = (
                "import os,subprocess,sys,time\n"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                f"open({str(pid_file)!r},'w').write(str(os.getpid())+' '+str(child.pid))\n"
                "time.sleep(60)\n"
            )
            helper_code = f"""
import importlib.util
import os
from pathlib import Path
import sys
import threading

module_path = Path({str(MODULE_PATH)!r})
spec = importlib.util.spec_from_file_location("signal_guard_inventory", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
client = object.__new__(module.GhClient)
client.executable = Path(sys.executable).resolve()
client.timeout_seconds = 10
client._active_processes = set()
client._process_lock = threading.RLock()
client._previous_signal_handlers = {{}}
client._signal_handler_callback = None
client._environment = {{"LC_ALL": "C"}}
client._verify_api_config_directory = lambda: None
client._verify_executable_directory = lambda: None
client._open_verified_executable = lambda: os.open(client.executable, os.O_RDONLY)
client._install_signal_guards()
client._run(("-c", {workload!r}), stdout_limit=128)
"""
            helper = subprocess.Popen(
                (sys.executable, "-c", helper_code),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(pid_file.exists())
            direct_pid, child_pid = map(int, pid_file.read_text().split())
            helper.send_signal(signal.SIGTERM)
            self.assertEqual(helper.wait(timeout=5), 128 + signal.SIGTERM)
            self.assertTrue(pid_is_gone(direct_pid))
            self.assertTrue(pid_is_gone(child_pid))

    def test_sigterm_rejects_queued_head_gets_after_latch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "head-get-pids"
            page = [
                rest_repository(f"sepahead/public-{index:02d}", 20_000 + index)
                for index in range(20)
            ]
            workload = (
                "import os,time\n"
                f"open({str(pid_file)!r},'a').write(str(os.getpid())+'\\n')\n"
                "time.sleep(60)\n"
            )
            helper_code = f"""
import importlib.util
import os
from pathlib import Path
import sys
import threading

module_path = Path({str(MODULE_PATH)!r})
spec = importlib.util.spec_from_file_location("queued_head_inventory", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
client = object.__new__(module.GhClient)
client.executable = Path(sys.executable).resolve()
client.timeout_seconds = 60
client.head_workers = 2
client._active_processes = set()
client._process_lock = threading.RLock()
client._shutdown_requested = False
client._previous_signal_handlers = {{}}
client._signal_handler_callback = None
client._environment = {{"LC_ALL": "C"}}
client._verify_api_config_directory = lambda: None
client._verify_executable_directory = lambda: None
client._open_verified_executable = lambda: os.open(client.executable, os.O_RDONLY)
client._install_signal_guards()
page = {page!r}
rate = {RATE!r}

def get(endpoint, *, allow_empty_repository=False):
    del allow_empty_repository
    if endpoint == {PUBLIC_ENDPOINT!r}:
        return page, rate
    client._run(("-c", {workload!r}), stdout_limit=128)
    repository = endpoint.split("/", 3)[2]
    return {{"object": {{"sha": "1" * 40, "type": "commit"}}}}, rate

client.get = get
try:
    module.collect_snapshot(
        client,
        scope="PUBLIC",
        owner={OWNER!r},
        minimum_remaining=100,
        maximum_pages=2,
    )
finally:
    client.close()
"""
            helper = subprocess.Popen(
                (sys.executable, "-c", helper_code),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if pid_file.exists() and len(pid_file.read_text().splitlines()) >= 2:
                    break
                time.sleep(0.02)
            self.assertTrue(pid_file.exists())
            initial_pids = [int(value) for value in pid_file.read_text().splitlines()]
            self.assertEqual(len(initial_pids), 2)
            helper.send_signal(signal.SIGTERM)
            self.assertEqual(helper.wait(timeout=5), 128 + signal.SIGTERM)
            final_pids = [int(value) for value in pid_file.read_text().splitlines()]
            self.assertEqual(final_pids, initial_pids)
            for process_id in final_pids:
                self.assertTrue(pid_is_gone(process_id))

    def test_signal_latch_precedes_process_lock_and_rejects_queued_admission(
        self,
    ) -> None:
        client = process_test_client(timeout_seconds=2)
        client._shutdown_requested = False
        lock_held = threading.Event()
        handler_starting = threading.Event()
        waiter_ready = threading.Event()
        latch_observations: list[bool] = []
        waiter_errors: list[BaseException] = []

        def hold_process_lock() -> None:
            with client._process_lock:
                lock_held.set()
                if not handler_starting.wait(timeout=2):
                    latch_observations.append(False)
                    return
                deadline = time.monotonic() + 0.5
                while not client._shutdown_requested and time.monotonic() < deadline:
                    time.sleep(0.001)
                latch_observations.append(client._shutdown_requested)

        def open_verified_executable() -> int:
            waiter_ready.set()
            return os.open(client.executable, os.O_RDONLY)

        def queued_run() -> None:
            try:
                client._run(("-c", "pass"), stdout_limit=128)
            except BaseException as error:
                waiter_errors.append(error)

        client._open_verified_executable = open_verified_executable
        holder = threading.Thread(target=hold_process_lock)
        waiter = threading.Thread(target=queued_run)
        holder.start()
        self.assertTrue(lock_held.wait(timeout=2))
        waiter.start()
        self.assertTrue(waiter_ready.wait(timeout=2))
        with mock.patch.object(inventory.subprocess, "Popen") as popen:
            handler_starting.set()
            with self.assertRaises(SystemExit) as raised:
                client._handle_signal(signal.SIGTERM, None)
        holder.join(timeout=2)
        waiter.join(timeout=2)
        self.assertFalse(holder.is_alive())
        self.assertFalse(waiter.is_alive())
        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        self.assertEqual(latch_observations, [True])
        self.assertEqual(len(waiter_errors), 1)
        self.assertIsInstance(waiter_errors[0], inventory.InventoryError)
        self.assertEqual(str(waiter_errors[0]), "GH_SHUTDOWN")
        popen.assert_not_called()

    def test_external_signal_guard_kills_process_group_on_sigterm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "pids"
            workload = (
                "import os,subprocess,sys,time\n"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                f"open({str(pid_file)!r},'w').write(str(os.getpid())+' '+str(child.pid))\n"
                "time.sleep(60)\n"
            )
            helper_code = f"""
import importlib.util
from pathlib import Path
import sys

module_path = Path({str(MODULE_PATH)!r})
spec = importlib.util.spec_from_file_location("external_signal_inventory", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module._run_bounded_process(
    Path(sys.executable).resolve(),
    ("-c", {workload!r}),
    environment={{"LC_ALL": "C"}},
    stdout_limit=128,
    stderr_limit=128,
    timeout_seconds=10,
)
"""
            helper = subprocess.Popen(
                (sys.executable, "-c", helper_code),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(pid_file.exists())
            direct_pid, child_pid = map(int, pid_file.read_text().split())
            helper.send_signal(signal.SIGTERM)
            self.assertEqual(helper.wait(timeout=5), 128 + signal.SIGTERM)
            self.assertTrue(pid_is_gone(direct_pid))
            self.assertTrue(pid_is_gone(child_pid))

    def test_external_process_rejects_detached_stdio_descendants_after_exit(
        self,
    ) -> None:
        for return_code in (0, 7):
            with (
                self.subTest(return_code=return_code),
                tempfile.TemporaryDirectory() as temporary,
            ):
                pid_file = Path(temporary) / "child.pid"
                workload = (
                    "import subprocess,sys\n"
                    "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
                    "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                    "stderr=subprocess.DEVNULL)\n"
                    f"open({str(pid_file)!r},'w').write(str(child.pid))\n"
                    f"raise SystemExit({return_code})\n"
                )
                self.assert_inventory_error(
                    "EXTERNAL_PROCESS_DESCENDANT",
                    inventory._run_bounded_process,
                    Path(sys.executable).resolve(),
                    ("-c", workload),
                    environment={"LC_ALL": "C"},
                    stdout_limit=128,
                    stderr_limit=128,
                    timeout_seconds=5,
                )
                child_pid = int(pid_file.read_text(encoding="utf-8"))
                self.assertTrue(pid_is_gone(child_pid))
        self.assert_inventory_error(
            "EXTERNAL_PROCESS_STATUS",
            inventory._run_bounded_process,
            Path(sys.executable).resolve(),
            ("-c", "raise SystemExit(7)"),
            environment={"LC_ALL": "C"},
            stdout_limit=128,
            stderr_limit=128,
            timeout_seconds=5,
        )

    def test_identity_requires_exact_owner_viewer_equality(self) -> None:
        client = FakeRestClient()
        client.queue("/users/sepahead", identity_payload())
        client.queue("/user", identity_payload(account_id=OWNER["account_id"] + 1))
        self.assert_inventory_error(
            "VIEWER_OWNER_MISMATCH",
            inventory.verify_identity,
            client,
            "sepahead",
            minimum_remaining=100,
        )

    def test_two_page_capture_is_bounded_and_deterministic(self) -> None:
        first = rest_repository("sepahead/a", 1)
        second = rest_repository("sepahead/b", 2)
        third = rest_repository("sepahead/c", 3)
        client = FakeRestClient()
        page_two = inventory.PUBLIC_ENDPOINT_TEMPLATE.format(owner="sepahead", page=2)
        client.queue(PUBLIC_ENDPOINT, [second, first])
        client.queue(page_two, [third])
        for record in (first, second, third):
            queue_repository_heads(client, record, repetitions=1)
        with mock.patch.object(inventory, "MAX_PAGE_NODES", 2):
            records, summary = inventory.collect_snapshot(
                client,
                scope="PUBLIC",
                owner=OWNER,
                minimum_remaining=100,
                maximum_pages=2,
            )
        self.assertEqual(
            [record["repository"] for record in records],
            ["sepahead/a", "sepahead/b", "sepahead/c"],
        )
        self.assertEqual(summary["pages"], 2)
        self.assertEqual(summary["requests"], 5)
        client.assert_consumed()

    def test_page_bound_rejects_an_unfetched_descendant_page(self) -> None:
        first = rest_repository("sepahead/a", 1)
        second = rest_repository("sepahead/b", 2)
        client = FakeRestClient()
        client.queue(PUBLIC_ENDPOINT, [first, second])
        queue_repository_heads(client, first, repetitions=1)
        queue_repository_heads(client, second, repetitions=1)
        with mock.patch.object(inventory, "MAX_PAGE_NODES", 2):
            self.assert_inventory_error(
                "PAGE_LIMIT",
                inventory.collect_snapshot,
                client,
                scope="PUBLIC",
                owner=OWNER,
                minimum_remaining=100,
                maximum_pages=1,
            )

    def test_duplicate_repository_id_or_name_is_rejected(self) -> None:
        first = rest_repository("sepahead/a", 1)
        duplicate_id = rest_repository("sepahead/b", 1)
        client = FakeRestClient()
        client.queue(PUBLIC_ENDPOINT, [first, duplicate_id])
        queue_repository_heads(client, first, repetitions=1)
        queue_repository_heads(client, duplicate_id, repetitions=1)
        self.assert_inventory_error(
            "DUPLICATE_REPOSITORY",
            inventory.collect_snapshot,
            client,
            scope="PUBLIC",
            owner=OWNER,
            minimum_remaining=100,
            maximum_pages=2,
        )

    def test_malformed_39_hex_head_is_rejected(self) -> None:
        record = rest_repository("sepahead/a", 1)
        client = FakeRestClient()
        client.queue(PUBLIC_ENDPOINT, [record])
        client.queue(ref_endpoint("sepahead/a"), ref_payload("main", "a" * 39))
        self.assert_inventory_error(
            "DEFAULT_HEAD_OID",
            inventory.collect_snapshot,
            client,
            scope="PUBLIC",
            owner=OWNER,
            minimum_remaining=100,
            maximum_pages=2,
        )

    def test_empty_repository_uses_explicit_empty_state(self) -> None:
        record = rest_repository("sepahead/empty", 7, default_branch="main")
        client = FakeRestClient()
        client.queue(PUBLIC_ENDPOINT, [record])
        client.queue(ref_endpoint("sepahead/empty"), None)
        records, _summary = inventory.collect_snapshot(
            client,
            scope="PUBLIC",
            owner=OWNER,
            minimum_remaining=100,
            maximum_pages=2,
        )
        self.assertEqual(records[0]["head_state"], "EMPTY_REPOSITORY")
        self.assertIsNone(records[0]["default_branch"])
        self.assertIsNone(records[0]["exact_head"])
        client.assert_consumed()

    def test_rate_reserve_is_enforced_before_repository_expansion(self) -> None:
        client = FakeRestClient()
        client.queue(
            PUBLIC_ENDPOINT,
            [],
            rate={
                "attempts": 1,
                "remaining": 99,
                "reset_at_utc": RATE["reset_at_utc"],
            },
        )
        self.assert_inventory_error(
            "RATE_RESERVE",
            inventory.collect_snapshot,
            client,
            scope="PUBLIC",
            owner=OWNER,
            minimum_remaining=100,
            maximum_pages=2,
        )

    def test_page_budget_reserves_every_planned_head_get(self) -> None:
        record = rest_repository("sepahead/a", 1)
        client = FakeRestClient()
        client.queue(
            PUBLIC_ENDPOINT,
            [record],
            rate={
                "attempts": 1,
                "remaining": 100,
                "reset_at_utc": RATE["reset_at_utc"],
            },
        )
        self.assert_inventory_error(
            "RATE_PAGE_BUDGET",
            inventory.collect_snapshot,
            client,
            scope="PUBLIC",
            owner=OWNER,
            minimum_remaining=100,
            maximum_pages=2,
        )

    def test_double_capture_rejects_exact_head_drift(self) -> None:
        public_record = rest_repository("sepahead/a", 1)
        client = FakeRestClient()
        client.queue("/users/sepahead", identity_payload())
        client.queue("/user", identity_payload())
        client.queue(PUBLIC_ENDPOINT, [public_record], [public_record])
        client.queue(
            ref_endpoint("sepahead/a"),
            ref_payload("main", "1" * 40),
            ref_payload("main", "2" * 40),
        )
        self.assert_inventory_error(
            "SNAPSHOT_DRIFT",
            inventory.capture_account,
            client,
            owner_name="sepahead",
            minimum_remaining=100,
            maximum_pages=2,
        )

    def test_public_subset_equality_is_exact(self) -> None:
        public_record = rest_repository("sepahead/a", 1, language="Rust")
        owner_public = rest_repository("sepahead/a", 1, language="Python")
        private_record = rest_repository(PRIVATE_CANARY, 9, visibility="private")
        client = FakeRestClient()
        client.queue("/users/sepahead", identity_payload())
        client.queue("/user", identity_payload())
        client.queue(PUBLIC_ENDPOINT, [public_record], [public_record])
        client.queue(
            OWNER_ENDPOINT,
            [owner_public, private_record],
            [owner_public, private_record],
        )
        queue_repository_heads(client, public_record, repetitions=2)
        queue_repository_heads(client, owner_public, repetitions=2)
        queue_repository_heads(client, private_record, repetitions=2)
        self.assert_inventory_error(
            "PUBLIC_SUBSET_MISMATCH",
            inventory.capture_account,
            client,
            owner_name="sepahead",
            minimum_remaining=100,
            maximum_pages=2,
        )

    def test_template_is_explicitly_unresolved_and_cannot_render(self) -> None:
        raw = rest_repository("sepahead/a", 1)
        client = FakeRestClient()
        client.queue(PUBLIC_ENDPOINT, [raw])
        queue_repository_heads(client, raw, repetitions=1)
        heads, _summary = inventory.collect_snapshot(
            client,
            scope="PUBLIC",
            owner=OWNER,
            minimum_remaining=100,
            maximum_pages=2,
        )
        template = inventory.decision_template(heads)
        self.assertEqual(template["records"][0]["tcb_class"], "UNRESOLVED")
        self.assert_inventory_error(
            "DECISION_AGENTIC", inventory.validate_decisions, template, heads
        )

    def test_decisions_require_exact_keys_identity_order_and_coverage(self) -> None:
        first = {
            **self._normalized_head("sepahead/a", 1),
            "fork": False,
        }
        second = {
            **self._normalized_head("sepahead/b", 2),
            "fork": False,
        }
        captures = [first, second]
        valid = resolved_decisions(captures)
        self.assertEqual(len(inventory.validate_decisions(valid, captures)), 2)

        missing = copy.deepcopy(valid)
        missing["records"].pop()
        self.assert_inventory_error(
            "DECISIONS_COUNT", inventory.validate_decisions, missing, captures
        )

        wrong_name = copy.deepcopy(valid)
        wrong_name["records"][0]["repository"] = "sepahead/not-a"
        self.assert_inventory_error(
            "DECISION_CAPTURE_MATCH", inventory.validate_decisions, wrong_name, captures
        )

        reordered = copy.deepcopy(valid)
        reordered["records"].reverse()
        self.assert_inventory_error(
            "DECISION_ORDER_OR_COVERAGE",
            inventory.validate_decisions,
            reordered,
            captures,
        )

        wildcard = copy.deepcopy(valid)
        wildcard["records"][0]["default"] = "allow"
        self.assert_inventory_error(
            "DECISION_KEYS", inventory.validate_decisions, wildcard, captures
        )

        placeholder = copy.deepcopy(valid)
        placeholder["records"][0]["reviewer"] = "TBD"
        self.assert_inventory_error(
            "DECISION_REVIEWER",
            inventory.validate_decisions,
            placeholder,
            captures,
        )

        false_basis = copy.deepcopy(valid)
        false_basis["classification_review_basis"][
            "completed_runtime_integration_inferred"
        ] = True
        self.assert_inventory_error(
            "DECISIONS_REVIEW_BASIS",
            inventory.validate_decisions,
            false_basis,
            captures,
        )

        unbound_source = copy.deepcopy(valid)
        unbound_source["classification_review_basis"]["maintained_source_ids"].append(
            "UNBOUND_SOURCE"
        )
        self.assert_inventory_error(
            "DECISIONS_REVIEW_BASIS",
            inventory.validate_decisions,
            unbound_source,
            captures,
        )

    def test_fork_status_does_not_infer_first_party_or_tcb_class(self) -> None:
        head = self._normalized_head("sepahead/fork", 3)
        head["fork"] = True
        decisions = resolved_decisions([head])
        decisions["records"][0]["first_party"] = True
        decisions["records"][0]["tcb_class"] = "GATE_RUNTIME_TCB"
        validated = inventory.validate_decisions(decisions, [head])
        self.assertTrue(validated[0]["first_party"])
        self.assertEqual(validated[0]["tcb_class"], "GATE_RUNTIME_TCB")

    def test_csv_is_stable_and_quotes_authored_commas(self) -> None:
        head = self._normalized_head("sepahead/a", 1)
        decisions = resolved_decisions(
            [head], justification='Explicit review, including "quoted" evidence.'
        )
        joined = inventory.joined_records(
            [head], inventory.validate_decisions(decisions, [head])
        )
        payload = inventory.classification_csv(joined)
        self.assertEqual(payload, inventory.classification_csv(joined))
        self.assertIn(b'"Explicit review, including ""quoted"" evidence."', payload)

        decisions["records"][0]["justification"] = (
            "=HYPERLINK(unsafe) with explicit reviewed rationale."
        )
        formula_joined = inventory.joined_records(
            [head], inventory.validate_decisions(decisions, [head])
        )
        self.assertIn(
            b"'=HYPERLINK(unsafe) with explicit reviewed rationale.",
            inventory.classification_csv(formula_joined),
        )

    def test_end_to_end_render_and_both_check_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            offline = inventory.check_files(
                root=paths["root"],
                owner_visible=None,
                private_decisions=None,
                _test_profile=True,
            )
            self.assertEqual(
                offline,
                {
                    "private_scope": "COMMITMENT_ONLY",
                    "public": 1,
                    "seal_state": "COMMITMENT_ONLY_NOT_VERIFIED",
                },
            )
            owner_local = inventory.check_files(
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )
            self.assertEqual(
                owner_local,
                {
                    "private_scope": "OWNER_LOCAL_VERIFIED",
                    "public": 1,
                    "seal_state": "AUDIT_STAGED_FINAL",
                },
            )

    def test_private_files_are_exact_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            for path in (
                paths["owner_visible"],
                paths["private_decisions"],
                paths["root"] / "local-private-source-ledger.private.csv",
            ):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            os.chmod(paths["private_decisions"], 0o644)
            self.assert_inventory_error(
                "PRIVATE_MODE",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_private_canary_never_enters_public_products_or_cli_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            public_names = (
                "repository-heads.jsonl",
                "capture-metadata.json",
                "command-log.jsonl",
                "repository-classification-decisions.json",
                "repository-classification.json",
                "repository-classification.csv",
                "audit-metadata.json",
            )
            canary = PRIVATE_CANARY.encode("utf-8")
            for name in public_names:
                self.assertNotIn(canary, (paths["root"] / name).read_bytes(), name)

            private_value, _payload = inventory._load_json(paths["private_decisions"])
            private_value["records"][0]["repository"] = PRIVATE_CANARY + "-wrong"
            inventory._atomic_write(
                paths["private_decisions"],
                inventory.canonical_json(private_value),
                private=True,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = inventory.main(
                    [
                        "check",
                        "--root",
                        str(paths["root"]),
                        "--owner-visible",
                        str(paths["owner_visible"]),
                        "--private-decisions",
                        str(paths["private_decisions"]),
                    ]
                )
            self.assertEqual(result, 1)
            emitted = (stdout.getvalue() + stderr.getvalue()).encode("utf-8")
            self.assertNotIn(canary, emitted)
            self.assertNotIn(b"-wrong", emitted)

    def test_private_identifiers_in_public_authored_text_fail_before_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            public_outputs = (
                paths["root"] / inventory.PUBLIC_CLASSIFICATION_JSON_BASENAME,
                paths["root"] / inventory.PUBLIC_CLASSIFICATION_CSV_BASENAME,
                paths["root"] / inventory.AUDIT_METADATA_BASENAME,
            )
            before = {path: path.read_bytes() for path in public_outputs}
            decisions, _payload = inventory._load_json(paths["public_decisions"])
            decisions["records"][0]["justification"] = (
                f"Reviewed {PRIVATE_CANARY.rsplit('/', 1)[-1]} as a private canary."
            )
            inventory._atomic_write(
                paths["public_decisions"],
                inventory.canonical_json(decisions),
                private=False,
            )
            self.assert_inventory_error(
                "PRIVATE_IDENTIFIER_PUBLIC_LEAK",
                inventory.render_files,
                public_heads=paths["public_heads"],
                owner_visible=paths["owner_visible"],
                public_decisions=paths["public_decisions"],
                private_decisions=paths["private_decisions"],
                capture_metadata=paths["capture_metadata"],
                command_log=paths["command_log"],
                output_root=paths["root"],
                supersession_audit=paths["supersession_audit"],
                _test_profile=True,
            )
            self.assertEqual(
                before, {path: path.read_bytes() for path in public_outputs}
            )

    def test_cross_lane_scan_is_precise_for_ids_names_and_urls(self) -> None:
        public = self._normalized_head("sepahead/public", 1)
        private = self._normalized_head(PRIVATE_CANARY, 9_001)
        private["visibility"] = "PRIVATE"
        private_names, private_urls, private_ids = inventory._private_identifier_tokens(
            [private], [public]
        )
        for value in (
            {"repository_id": 9_001},
            f"See {PRIVATE_CANARY}.",
            f"See https://github.com/{PRIVATE_CANARY}.",
            f"github.com/{PRIVATE_CANARY}",
            f"http://github.com/{PRIVATE_CANARY}",
            f"https://www.github.com/{PRIVATE_CANARY}",
            f"prefix/{PRIVATE_CANARY}",
            f"https://example.test/path?repository={PRIVATE_CANARY}",
            f"https://example.test/path#repository={PRIVATE_CANARY}",
            f"git@github.com:{PRIVATE_CANARY}.git",
            f"/repos/{PRIVATE_CANARY}",
            f"https://github.com/{PRIVATE_CANARY}.git",
        ):
            with self.subTest(value=value):
                self.assert_inventory_error(
                    "PRIVATE_IDENTIFIER_PUBLIC_LEAK",
                    inventory._scan_public_value,
                    value,
                    private_names=private_names,
                    private_urls=private_urls,
                    private_ids=private_ids,
                )
        inventory._scan_public_value(
            {
                "bytes": 9_001,
                "justification": f"Branch main and object {private['exact_head']} are not identity tokens.",
                "bare_branch_collision": PRIVATE_CANARY.split("/", 1)[1],
                "hyphenated_public_prefix_neighbor": f"{PRIVATE_CANARY}-plus",
                "dotted_public_prefix_neighbor": f"{PRIVATE_CANARY}.tools",
                "underscored_public_prefix_neighbor": f"{PRIVATE_CANARY}_tools",
            },
            private_names=private_names,
            private_urls=private_urls,
            private_ids=private_ids,
        )

    def test_cross_lane_scan_rejects_contextual_short_private_identifiers(self) -> None:
        public = self._normalized_head("sepahead/public", 1)
        public["exact_head"] = "1234567890abcdef1234567890abcdef12345678"
        private = self._normalized_head("sepahead/foo", 9_001)
        private["default_branch"] = "qa"
        private["exact_head"] = "abcdef1234567890abcdef1234567890abcdef12"
        private["visibility"] = "PRIVATE"
        private_names, private_urls, private_ids = inventory._private_identifier_tokens(
            [private], [public]
        )
        bounded, exact, contextual = inventory._private_raw_identifier_tokens(
            [private], [public]
        )
        private_head = str(private["exact_head"])
        leaks = (
            "branch qa",
            "branch: qa",
            "branch=qa",
            '{"branch":"qa"}',
            '{"default_branch":"qa"}',
            "git checkout qa",
            "git checkout -b qa",
            "git switch qa",
            "git switch -c qa",
            "refs/heads/qa",
            "foo.git",
            "git clone foo.git",
            "git clone foo",
            "gh repo clone foo",
            "private repository foo",
            "repository: foo",
            "repo=foo",
            f"head: {private_head[:7]}",
            f"head: {private_head[:4]}",
            f"commit {private_head[:12]}",
            f"oid={private_head[:39]}",
            f"private-head-{private_head}",
            f"commit_{private_head}",
            f"{private_head}.patch",
            private_head.upper(),
            "repository_id: 9001",
            "repository-id: '9001'",
            "repo_id=9001",
            "repo id 9001",
            "repo_id,9001",
            '{"repository_id":"9001"}',
            '{"repository\\u005fid":"9001"}',
            {"repository_id": "9001"},
            {"repo-id": "9001"},
            '{"defaultBranch":"qa"}',
            '{"default-branch":"qa"}',
            '{"headRefName":"qa"}',
            '{"ref":"qa"}',
            {"defaultBranch": "qa"},
            {"default-branch": "qa"},
            {"headRefName": "qa"},
            {"ref": "qa"},
            {"sha": "qa"},
            {"defaultBranchRef": {"name": "qa"}},
            {
                "defaultBranchRef": {
                    "target": {"oid": str(public["exact_head"])},
                    "name": "qa",
                }
            },
            '{"sha":"qa"}',
            "sha=qa",
            "branch-qa.md",
            "branch.qa.remote=origin",
            "default_branch_qa.json",
            "branch/qa",
            "/branches/qa",
            "/commits/qa",
            "/tree/qa",
            "refs/remotes/origin/qa",
            '{"repositoryName":"foo"}',
            '{"repo_name":"foo"}',
            {"repositoryName": "foo"},
            {"repo_name": "foo"},
            {"repository": {"name": "foo"}},
            "repository-foo.md",
            "repo_foo.txt",
            "repository/foo",
            "repo/foo",
            f'{{"commitSha":"{private_head[:7]}"}}',
            f'{{"head_sha":"{private_head[:7]}"}}',
            f'{{"headOid":"{private_head[:7]}"}}',
            {"commitSha": private_head[:7]},
            {"head_sha": private_head[:7]},
            {"headOid": private_head[:7]},
            f"commit-{private_head[:7]}.patch",
            f"commits/{private_head[:7]}",
            f"head_{private_head[:4]}",
            f"oid/{private_head[:7]}",
            {"repository": {"databaseId": 9001}},
            {"repository": {"id": "9001"}},
            {"repositories": [{"databaseId": 9001}]},
            {"repositories": {"nodes": [{"databaseId": "9001"}]}},
            {"repository": {"node": {"databaseId": 9001}}},
            {"repository": {"metadata": {"id": 9001}}},
            {"repository": {"metadata": {"name": "foo"}}},
            {"repositories": {"nodes": [{"name": "foo"}]}},
            '{"repository":{"databaseId":9001}}',
            '{"repository":{"id":"9001"}}',
            '{"repository":{"id":"\\u0039\\u0030\\u0030\\u0031"}}',
            '{"repositories":[{"databaseId":9001}]}',
            '{"repositories":{"nodes":[{"databaseId":9001}]}}',
            '{"repository":{"node":{"databaseId":9001}}}',
            '{"repository":{"metadata":{"id":9001}}}',
            '{"repository":{"metadata":{"name":"foo"}}}',
            '{"repositories":{"nodes":[{"name":"foo"}]}}',
            (
                '{"defaultBranchRef":{"target":{"oid":"'
                f"{public['exact_head']}"
                '"},"name":"qa"}}'
            ),
            "/repositories/9001",
            "https://api.github.com/repositories/9001",
            "github.event.repository.name=foo",
            "github.event.repository.id=9001",
            "repository/databaseId/9001",
            "repositories.nodes.databaseId=9001",
            '[submodule "foo"]',
            "submodule=foo",
            "remote.origin.url=../foo",
            "git remote add origin ../foo",
            "git fetch foo",
            "git fetch ../foo",
            "git fetch /tmp/review/foo.git",
            "git -C foo status",
            "git -C ../foo status",
            'git -C "/tmp/review/foo" status',
            f"object {private_head[:7]}",
            f"git rev-parse {private_head[:7]}",
            "repo-id-9001.json",
            "repository-id-9001.json",
            "repo_id_9001.json",
            "repository_id_9001.json",
        )
        escaped_repository = "".join(
            f"\\u{ord(character):04x}" for character in str(private["repository"])
        )
        escaped_branch = "".join(
            f"\\u{ord(character):04x}" for character in str(private["default_branch"])
        )
        escaped_url = str(private["canonical_url"]).replace("/", "\\/")
        leaks = (
            *leaks,
            f'{{"repository":"{escaped_repository}"}}',
            f'{{"branch":"{escaped_branch}"}}',
            f'{{"canonical_url":"{escaped_url}"}}',
        )
        for value in leaks:
            with self.subTest(value=value):
                self.assert_inventory_error(
                    "PRIVATE_IDENTIFIER_PUBLIC_LEAK",
                    inventory._scan_public_value,
                    value,
                    private_names=private_names,
                    private_urls=private_urls,
                    private_ids=private_ids,
                    private_bounded_tokens=bounded,
                    private_exact_literals=exact,
                    private_contextual_tokens=contextual,
                )
        for allowed in (
            "qa",
            "The quality branch is public context.",
            "main",
            str(public["exact_head"]),
            "repository food",
            "branch quality",
            "9001",
            "bytes=9001",
            {"name": "qa"},
            {"name": "foo"},
            {"bytes": "9001"},
            {"repository": {"owner": {"name": "foo", "id": 9001}}},
            {
                "repository": {
                    "owner": {"databaseId": 9001},
                    "issues": {"nodes": [{"id": 9001, "name": "foo"}]},
                }
            },
            {
                "repositories": {
                    "nodes": [{"issues": [{"databaseId": 9001, "name": "foo"}]}]
                }
            },
            '{"repository":{"owner":{"name":"foo","id":9001}}}',
            '{"repository":{"issues":{"nodes":[{"id":9001,"name":"foo"}]}}}',
            "repository.owner.name=foo",
            "repository.owner.id=9001",
            "repository.issues.nodes.0.id=9001",
            "repositories.nodes.0.issues.0.databaseId=9001",
            "git fetch ../food",
            "git -C ../food status",
        ):
            with self.subTest(allowed=allowed):
                inventory._scan_public_value(
                    allowed,
                    private_names=private_names,
                    private_urls=private_urls,
                    private_ids=private_ids,
                    private_bounded_tokens=bounded,
                    private_exact_literals=exact,
                    private_contextual_tokens=contextual,
                )

    def test_compiled_privacy_policy_is_bounded_cached_and_precise(self) -> None:
        private_names = frozenset({"sepahead/private-canary"})
        private_urls = frozenset({"https://github.com/sepahead/private-canary"})
        private_bounded = frozenset(
            {
                "abcdef1234567890abcdef1234567890abcdef12",
                "private-canary",
            }
        )
        private_exact = frozenset({"repository id: 9001"})
        private_contextual = frozenset(
            (
                "oid_prefix",
                "abcdef1234567890abcdef1234567890abcdef12"[:end],
            )
            for end in range(4, 40)
        ) | frozenset(
            {
                ("branch", "qa"),
                ("git_basename", "private-canary"),
                ("repository", "private-canary"),
                ("repository_id", "9001"),
            }
        )
        inventory._compiled_private_text_patterns.cache_clear()
        first = inventory._compiled_private_text_patterns(
            private_names,
            private_urls,
            private_bounded,
            private_exact,
            private_contextual,
        )
        second = inventory._compiled_private_text_patterns(
            private_names,
            private_urls,
            private_bounded,
            private_exact,
            private_contextual,
        )
        self.assertIs(first, second)
        self.assertLessEqual(len(first), 10)
        cache = inventory._compiled_private_text_patterns.cache_info()
        self.assertEqual((cache.hits, cache.misses), (1, 1))
        for leak in (
            "git fetch ../private-canary",
            "git -C /tmp/private-canary status",
            "head: abcdef1",
            "repository id: 9001",
        ):
            with self.subTest(leak=leak):
                self.assertTrue(
                    inventory._contains_private_identifier_text_direct(
                        leak,
                        private_names=private_names,
                        private_urls=private_urls,
                        private_bounded_tokens=private_bounded,
                        private_exact_literals=private_exact,
                        private_contextual_tokens=private_contextual,
                    )
                )
        for allowed in (
            "git fetch ../private-canary-tools",
            "git -C /tmp/private-canary-tools status",
            "head: abcdeg1",
            "repository id: 9010",
        ):
            with self.subTest(allowed=allowed):
                self.assertFalse(
                    inventory._contains_private_identifier_text_direct(
                        allowed,
                        private_names=private_names,
                        private_urls=private_urls,
                        private_bounded_tokens=private_bounded,
                        private_exact_literals=private_exact,
                        private_contextual_tokens=private_contextual,
                    )
                )

    def test_json_representation_budget_accepts_unpaired_surrogate_text(self) -> None:
        self.assertEqual(
            inventory._decoded_json_string_representations(
                "\ud800\\still-escaped"
            ),
            (),
        )

    def test_embedded_json_budget_accepts_unpaired_surrogate_text(self) -> None:
        self.assertFalse(
            inventory._contains_private_identifier_in_embedded_json(
                ("\ud800{}",),
                private_ids=frozenset(),
                private_contextual_tokens=frozenset(),
            )
        )

    def test_compiled_privacy_alternatives_match_singleton_policies(self) -> None:
        private_names = frozenset(
            {
                "sepahead/foo",
                "sepahead/foo-bar",
                "sepahead/foo.bar",
                "sepahead/foo_bar",
            }
        )
        private_urls = frozenset(
            f"https://github.com/{name}" for name in private_names
        )
        private_bounded = frozenset(
            {
                "0123456789abcdef0123456789abcdef01234567",
                "foo-bar",
                "foo.bar",
            }
        )
        private_exact = frozenset(
            {"literal-one", "literal.one", "literal[one]"}
        )
        private_contextual = frozenset(
            {
                ("branch", "qa"),
                ("branch", "qa-1"),
                ("git_basename", "foo"),
                ("git_basename", "foo-bar"),
                ("oid_prefix", "abcd"),
                ("oid_prefix", "abcdef1"),
                ("repository", "foo"),
                ("repository", "foo-bar"),
                ("repository", "foo.bar"),
                ("repository_id", "9001"),
                ("repository_id", "90010"),
            }
        )

        def singleton_match(value: str) -> bool:
            policies = [
                *(
                    (frozenset({token}), frozenset(), frozenset(), frozenset(), frozenset())
                    for token in private_names
                ),
                *(
                    (frozenset(), frozenset({token}), frozenset(), frozenset(), frozenset())
                    for token in private_urls
                ),
                *(
                    (frozenset(), frozenset(), frozenset({token}), frozenset(), frozenset())
                    for token in private_bounded
                ),
                *(
                    (frozenset(), frozenset(), frozenset(), frozenset({token}), frozenset())
                    for token in private_exact
                ),
                *(
                    (frozenset(), frozenset(), frozenset(), frozenset(), frozenset({token}))
                    for token in private_contextual
                ),
            ]
            return any(
                inventory._contains_private_identifier_text_direct(
                    value,
                    private_names=names,
                    private_urls=urls,
                    private_bounded_tokens=bounded,
                    private_exact_literals=exact,
                    private_contextual_tokens=contextual,
                )
                for names, urls, bounded, exact, contextual in policies
            )

        cases = (
            ("https://github.com/sepahead/foo.git", True),
            ("https://github.com/sepahead/foo.tools", False),
            ("literal[one]", True),
            ("literal[x]", False),
            ("branch: qa-1", True),
            ("branch: quality", False),
            ("repository: foo.bar", True),
            ("repository: food", False),
            ("foo-bar.git", True),
            ("foo-bars.git", False),
            ("head: abcdef1", True),
            ("head: abcdeg1", False),
            ("repository id: 90010", True),
            ("repository id: 900100", False),
            ("standalone foo.bar", True),
            ("standalone foo.bar-tools", False),
            ("sepahead/foo_bar", True),
            ("sepahead/foo_bar-tools", False),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                combined = inventory._contains_private_identifier_text_direct(
                    value,
                    private_names=private_names,
                    private_urls=private_urls,
                    private_bounded_tokens=private_bounded,
                    private_exact_literals=private_exact,
                    private_contextual_tokens=private_contextual,
                )
                self.assertEqual(combined, singleton_match(value))
                self.assertIs(combined, expected)

    def test_production_cardinality_privacy_policy_compiles_once(self) -> None:
        public = self._normalized_head("sepahead/public", 1)
        public["exact_head"] = "f" * 40
        private_records = []
        for index in range(1, 44):
            record = self._normalized_head(
                f"sepahead/private-{index:02d}", 9_000 + index
            )
            record["default_branch"] = f"private-{index:02d}-branch"
            record["exact_head"] = (
                f"{index:04x}"
                + hashlib.sha256(str(index).encode("ascii")).hexdigest()[:36]
            )
            record["visibility"] = "PRIVATE"
            private_records.append(record)
        private_names, private_urls, _private_ids = (
            inventory._private_identifier_tokens(private_records, [public])
        )
        bounded, exact, contextual = inventory._private_raw_identifier_tokens(
            private_records, [public]
        )
        self.assertGreaterEqual(len(contextual), 1_548)
        safe_values = [
            f"ordinary public assurance document {index}"
            for index in range(2_000)
        ]
        inventory._compiled_private_text_patterns.cache_clear()
        inventory._verify_cross_lane_privacy(
            private_records=private_records,
            public_records=[public],
            public_values=(safe_values,),
            public_payloads=(inventory.canonical_json(safe_values),),
        )
        cache = inventory._compiled_private_text_patterns.cache_info()
        self.assertEqual(cache.misses, 1)
        self.assertGreaterEqual(cache.hits, len(safe_values))
        policy = inventory._compiled_private_text_patterns(
            private_names,
            private_urls,
            bounded,
            exact,
            contextual,
        )
        self.assertLessEqual(len(policy), 10)

    def test_owner_local_check_repeats_cross_lane_privacy_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            decisions, _payload = inventory._load_json(paths["public_decisions"])
            decisions["records"][0]["reviewer"] = (
                f"reviewer {PRIVATE_CANARY.rsplit('/', 1)[-1]}"
            )
            public_records, public_payload = inventory._load_jsonl(
                paths["public_heads"]
            )
            decision_payload = inventory.canonical_json(decisions)
            decision_records = inventory.validate_decisions(decisions, public_records)
            joined = inventory.joined_records(public_records, decision_records)
            generated_json = inventory.classification_json(
                joined,
                heads_sha256=inventory.sha256(public_payload),
                decisions_sha256=inventory.sha256(decision_payload),
            )
            generated_csv = inventory.classification_csv(joined)
            inventory._atomic_write(
                paths["public_decisions"], decision_payload, private=False
            )
            inventory._atomic_write(
                paths["root"] / inventory.PUBLIC_CLASSIFICATION_JSON_BASENAME,
                generated_json,
                private=False,
            )
            inventory._atomic_write(
                paths["root"] / inventory.PUBLIC_CLASSIFICATION_CSV_BASENAME,
                generated_csv,
                private=False,
            )
            audit, _payload = inventory._load_json(
                paths["root"] / inventory.AUDIT_METADATA_BASENAME
            )
            audit["public_evidence"]["sources"]["public_decisions"] = (
                inventory._file_record(
                    inventory.PUBLIC_DECISIONS_BASENAME,
                    decision_payload,
                    classification="PUBLIC_AUTHORED_SOURCE",
                )
            )
            audit["products"] = {
                "repository_classification_csv": inventory._file_record(
                    inventory.PUBLIC_CLASSIFICATION_CSV_BASENAME,
                    generated_csv,
                    classification="PUBLIC_GENERATED",
                ),
                "repository_classification_json": inventory._file_record(
                    inventory.PUBLIC_CLASSIFICATION_JSON_BASENAME,
                    generated_json,
                    classification="PUBLIC_GENERATED",
                ),
            }
            inventory._atomic_write(
                paths["root"] / inventory.AUDIT_METADATA_BASENAME,
                inventory.canonical_json(audit),
                private=False,
            )
            offline = inventory.check_files(
                root=paths["root"],
                owner_visible=None,
                private_decisions=None,
                _test_profile=True,
            )
            self.assertEqual(offline["private_scope"], "COMMITMENT_ONLY")
            self.assert_inventory_error(
                "PRIVATE_IDENTIFIER_PUBLIC_LEAK",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_git_privacy_closure_rejects_tracked_text_binary_and_path_leaks(
        self,
    ) -> None:
        cases = {
            "text": ("tracked-leak.md", PRIVATE_CANARY.encode("ascii")),
            "binary": (
                "tracked-binary.bin",
                b"\x00\xff" + PRIVATE_CANARY.encode("ascii") + b"\x00",
            ),
            "path": (f"prefix/{PRIVATE_CANARY}/public.txt", b"otherwise safe\n"),
        }
        for case, (relative, payload) in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                paths = self.capture_fixture(Path(temporary))
                target = paths["root"] / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                subprocess.run(
                    ("git", "-C", str(paths["root"]), "add", "--", relative),
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assert_inventory_error(
                    "PRIVATE_IDENTIFIER_TRACKED_LEAK",
                    inventory.check_files,
                    root=paths["root"],
                    owner_visible=paths["owner_visible"],
                    private_decisions=paths["private_decisions"],
                    _test_profile=True,
                )

    def test_git_privacy_closure_rejects_json_escaped_private_identifiers(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            arguments = self.closure_kwargs(
                paths,
                audit_payload=(root / inventory.AUDIT_METADATA_BASENAME).read_bytes(),
            )
            private_record = copy.deepcopy(arguments["private_records"][0])
            private_record["default_branch"] = "qa"
            private_record["repository"] = "sepahead/foo"
            private_record["canonical_url"] = "https://github.com/sepahead/foo"
            private_record["exact_head"] = "abcdef1234567890abcdef1234567890abcdef12"
            arguments["private_records"] = [private_record]
            escaped_repository = "".join(
                f"\\u{ord(character):04x}"
                for character in str(private_record["repository"])
            )
            escaped_url = str(private_record["canonical_url"]).replace("/", "\\/")
            cases = (
                ("escaped-repository.json", f'{{"repository":"{escaped_repository}"}}'),
                ("escaped-url.json", f'{{"canonical_url":"{escaped_url}"}}'),
                ("escaped-branch.json", '{"branch":"\\u0071\\u0061"}'),
                ("string-repository-id.json", '{"repository_id":"9001"}'),
                (
                    "escaped-repository-id.json",
                    '{"repository\\u005fid":"9001"}',
                ),
                ("repository-id.yaml", "repository-id: '9001'"),
                ("repository-id.csv", "repo_id,9001"),
                ("default-branch-camel.json", '{"defaultBranch":"qa"}'),
                ("default-branch-kebab.json", '{"default-branch":"qa"}'),
                ("head-ref-name.json", '{"headRefName":"qa"}'),
                ("short-ref.json", '{"ref":"qa"}'),
                ("short-sha.json", '{"sha":"qa"}'),
                ("nested-default-ref.json", '{"defaultBranchRef":{"name":"qa"}}'),
                (
                    "deep-default-ref.json",
                    '{"defaultBranchRef":{"target":{"oid":"1234567890abcdef1234567890abcdef12345678"},"name":"qa"}}',
                ),
                ("repository-name.json", '{"repositoryName":"foo"}'),
                ("repo-name.json", '{"repo_name":"foo"}'),
                ("nested-repository-name.json", '{"repository":{"name":"foo"}}'),
                ("commit-sha.json", '{"commitSha":"abcdef1"}'),
                ("head-sha.json", '{"head_sha":"abcdef1"}'),
                ("head-oid.json", '{"headOid":"abcdef1"}'),
                ("nested-database-id.json", '{"repository":{"databaseId":9001}}'),
                ("nested-string-id.json", '{"repository":{"id":"9001"}}'),
                (
                    "repositories-list-id.json",
                    '{"repositories":[{"databaseId":9001}]}',
                ),
                (
                    "repositories-nodes-id.json",
                    '{"repositories":{"nodes":[{"databaseId":9001}]}}',
                ),
                (
                    "repository-node-id.json",
                    '{"repository":{"node":{"databaseId":9001}}}',
                ),
                (
                    "repository-metadata-id.json",
                    '{"repository":{"metadata":{"id":9001}}}',
                ),
                (
                    "repository-metadata-name.json",
                    '{"repository":{"metadata":{"name":"foo"}}}',
                ),
                (
                    "repositories-nodes-name.json",
                    '{"repositories":{"nodes":[{"name":"foo"}]}}',
                ),
                (
                    "nested-escaped-id.json",
                    '{"repository":{"id":"\\u0039\\u0030\\u0030\\u0031"}}',
                ),
                ("branch-qa.md", "safe\n"),
                ("branch.qa.remote=origin", "safe\n"),
                ("default_branch_qa.json", "safe\n"),
                ("repository-foo.md", "safe\n"),
                ("repo_foo.txt", "safe\n"),
                ("commit-abcdef1.patch", "safe\n"),
                ("head_abcd", "safe\n"),
                ("repo-id-9001.json", "safe\n"),
                ("repository-id-9001.json", "safe\n"),
                ("repo_id_9001.json", "safe\n"),
                ("repository_id_9001.json", "safe\n"),
                ("repository/foo", "safe\n"),
                ("repo/foo", "safe\n"),
                ("branch/qa", "safe\n"),
                ("commit/abcdef1", "safe\n"),
                ("commits/abcdef1", "safe\n"),
                ("oid/abcdef1", "safe\n"),
                ("refs/remotes/origin/qa", "safe\n"),
                ("branches/qa", "safe\n"),
                ("tree/qa", "safe\n"),
                ("repositories/9001", "safe\n"),
                ("github.event.repository.name=foo", "safe\n"),
                ("github.event.repository.id=9001", "safe\n"),
                ("repository/databaseId/9001", "safe\n"),
                ("repositories.nodes.databaseId=9001", "safe\n"),
                ("submodule-config", '[submodule "foo"]\n'),
                ("remote-config", "remote.origin.url=../foo\n"),
                ("remote-command", "git remote add origin ../foo\n"),
                ("fetch-command", "git fetch foo\n"),
                ("worktree-command", "git -C foo status\n"),
                ("object-command", "object abcdef1\n"),
                ("rev-parse-command", "git rev-parse abcdef1\n"),
            )
            for relative, value in cases:
                with self.subTest(relative=relative):
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(value, encoding="utf-8")
                    subprocess.run(
                        ("git", "-C", str(root), "add", "--", relative),
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    self.assert_inventory_error(
                        "PRIVATE_IDENTIFIER_TRACKED_LEAK",
                        inventory._git_privacy_closure,
                        **arguments,
                    )
                    subprocess.run(
                        ("git", "-C", str(root), "rm", "--cached", "--", relative),
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    target.unlink()

    def test_git_privacy_closure_rejects_private_component_and_telemetry_copies(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            telemetry_path = paths["private_telemetry"]
            assert isinstance(root, Path)
            assert isinstance(telemetry_path, Path)
            telemetry = json.loads(telemetry_path.read_bytes())
            owner_summary = telemetry["summaries"]["OWNER_VISIBLE"][0]
            public_summary = telemetry["summaries"]["PUBLIC"][0]
            compact_summary = json.dumps(
                owner_summary,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            nested_summary_superset = copy.deepcopy(owner_summary)
            nested_summary_superset["rate_limit"]["annotation"] = "still private"
            extended_public_command = copy.deepcopy(telemetry["command_log"][1])
            extended_public_command["argv_template"].append("annotation")
            nested_rate_limit = copy.deepcopy(owner_summary["rate_limit"])
            wrapped_rate_limit = {"rate_limit_copy": nested_rate_limit}
            cases = (
                (
                    "private-component-copy",
                    "docs/telemetry-copy.json",
                    telemetry_path.read_bytes(),
                    "PRIVATE_COMPONENT_TRACKED_LEAK",
                ),
                (
                    "owner-summary-copy",
                    "docs/owner-summary.json",
                    inventory.canonical_json(owner_summary),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "owner-command-copy",
                    "docs/owner-command.json",
                    inventory.canonical_json(telemetry["command_log"][3]),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "public-summary-copy",
                    "docs/private-detailed-public-summary.json",
                    inventory.canonical_json(public_summary),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "public-command-copy",
                    "docs/private-detailed-public-command.json",
                    inventory.canonical_json(telemetry["command_log"][1]),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "rate-limit-copy",
                    "docs/private-rate-limit.json",
                    inventory.canonical_json(nested_rate_limit),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "wrapped-rate-limit-copy",
                    "docs/wrapped-private-rate-limit.json",
                    inventory.canonical_json(wrapped_rate_limit),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "wrapped-owner-summary",
                    "docs/wrapped-owner-summary.json",
                    inventory.canonical_json({"leak": owner_summary}),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "fenced-owner-summary",
                    "docs/fenced-owner-summary.md",
                    b"```json\n" + inventory.canonical_json(owner_summary) + b"```\n",
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "prose-compact-owner-summary",
                    "docs/prose-owner-summary.md",
                    b"Owner-visible telemetry: " + compact_summary + b"\n",
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "blockquote-compact-owner-summary",
                    "docs/quote-owner-summary.md",
                    b"> " + compact_summary + b"\n",
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "multiline-blockquote-owner-summary",
                    "docs/multiline-quote-owner-summary.md",
                    b"".join(
                        b"> " + line
                        for line in inventory.canonical_json(owner_summary).splitlines(
                            keepends=True
                        )
                    ),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "multiline-diff-owner-summary",
                    "docs/diff-owner-summary.patch",
                    b"".join(
                        b"+ " + line
                        for line in inventory.canonical_json(owner_summary).splitlines(
                            keepends=True
                        )
                    ),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "multiline-deletion-owner-summary",
                    "docs/deletion-owner-summary.patch",
                    b"".join(
                        b"- " + line
                        for line in inventory.canonical_json(owner_summary).splitlines(
                            keepends=True
                        )
                    ),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "crlf-fenced-owner-summary",
                    "docs/crlf-owner-summary.md",
                    b"```json\r\n"
                    + inventory.canonical_json(owner_summary).replace(b"\n", b"\r\n")
                    + b"```\r\n",
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "json-string-owner-summary",
                    "docs/string-owner-summary.json",
                    inventory.canonical_json({"leak": compact_summary.decode("utf-8")}),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "superset-owner-summary",
                    "docs/superset-owner-summary.json",
                    inventory.canonical_json(
                        {**owner_summary, "annotation": "still private-derived"}
                    ),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "nested-superset-owner-summary",
                    "docs/nested-superset-owner-summary.json",
                    inventory.canonical_json(nested_summary_superset),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "extended-public-command-list",
                    "docs/extended-public-command.json",
                    inventory.canonical_json(extended_public_command),
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "duplicate-json-member-sensitive-first",
                    "docs/duplicate-member-owner-summary.json",
                    b'{"leak":' + compact_summary + b',"leak":null}\n',
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
                (
                    "binary-prefix-owner-summary",
                    "docs/binary-owner-summary.bin",
                    b"\xff" + compact_summary,
                    "PRIVATE_TELEMETRY_TRACKED_LEAK",
                ),
            )
            for case, relative, payload, code in cases:
                with self.subTest(case=case):
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(payload)
                    subprocess.run(
                        ("git", "-C", str(root), "add", "--", relative),
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    self.assert_inventory_error(
                        code,
                        inventory.check_files,
                        root=root,
                        owner_visible=paths["owner_visible"],
                        private_decisions=paths["private_decisions"],
                        _test_profile=True,
                    )
                    subprocess.run(
                        ("git", "-C", str(root), "rm", "--cached", "--", relative),
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    target.unlink()

    def test_git_privacy_closure_rejects_index_change_after_blob_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            leak = paths["root"] / "late-tracked-leak.md"
            real_blob_payloads = inventory._git_blob_payloads

            def scan_then_stage(*args, **kwargs):
                result = real_blob_payloads(*args, **kwargs)
                leak.write_text(PRIVATE_CANARY, encoding="utf-8")
                subprocess.run(
                    (
                        "git",
                        "-C",
                        str(paths["root"]),
                        "add",
                        "--",
                        leak.name,
                    ),
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return result

            with mock.patch.object(
                inventory, "_git_blob_payloads", side_effect=scan_then_stage
            ):
                self.assert_inventory_error(
                    "GIT_INDEX_DRIFT",
                    inventory.check_files,
                    root=paths["root"],
                    owner_visible=paths["owner_visible"],
                    private_decisions=paths["private_decisions"],
                    _test_profile=True,
                )

    def test_git_privacy_closure_rejects_index_change_during_audit_blob_fetch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            late = root / "late-audit-fetch-stage.md"
            real_blob_payloads = inventory._git_blob_payloads
            calls = 0

            def stage_during_audit_fetch(*args, **kwargs):
                nonlocal calls
                calls += 1
                result = real_blob_payloads(*args, **kwargs)
                if calls == 2:
                    late.write_text("safe staged drift\n", encoding="utf-8")
                    subprocess.run(
                        ("git", "-C", str(root), "add", "--", late.name),
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                return result

            with mock.patch.object(
                inventory,
                "_git_blob_payloads",
                side_effect=stage_during_audit_fetch,
            ):
                self.assert_inventory_error(
                    "GIT_INDEX_DRIFT",
                    inventory.check_files,
                    root=root,
                    owner_visible=paths["owner_visible"],
                    private_decisions=paths["private_decisions"],
                    _test_profile=True,
                )
            self.assertGreaterEqual(calls, 2)

    def test_private_components_remain_exact_through_owner_local_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            real_closure = inventory._git_privacy_closure

            def mutate_before_closure(**kwargs):
                payload = paths["private_decisions"].read_bytes()
                inventory._atomic_write(
                    paths["private_decisions"], payload + b" ", private=True
                )
                return real_closure(**kwargs)

            with mock.patch.object(
                inventory,
                "_git_privacy_closure",
                side_effect=mutate_before_closure,
            ):
                self.assert_inventory_error(
                    "PRIVATE_COMPONENT_DRIFT",
                    inventory.check_files,
                    root=paths["root"],
                    owner_visible=paths["owner_visible"],
                    private_decisions=paths["private_decisions"],
                    _test_profile=True,
                )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            real_candidate_state = inventory._git_candidate_state
            calls = 0

            def mutate_after_final_candidate(*args, **kwargs):
                nonlocal calls
                calls += 1
                result = real_candidate_state(*args, **kwargs)
                if calls == 2:
                    payload = paths["private_telemetry"].read_bytes()
                    inventory._atomic_write(
                        paths["private_telemetry"], payload + b" ", private=True
                    )
                return result

            with mock.patch.object(
                inventory,
                "_git_candidate_state",
                side_effect=mutate_after_final_candidate,
            ):
                self.assert_inventory_error(
                    "PRIVATE_COMPONENT_DRIFT",
                    inventory.check_files,
                    root=paths["root"],
                    owner_visible=paths["owner_visible"],
                    private_decisions=paths["private_decisions"],
                    _test_profile=True,
                )
            self.assertEqual(calls, 2)

    def test_git_privacy_closure_rejects_force_added_private_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            subprocess.run(
                (
                    "git",
                    "-C",
                    str(paths["root"]),
                    "add",
                    "--force",
                    "--",
                    inventory.OWNER_VISIBLE_BASENAME,
                ),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "PRIVATE_GIT_TRACKING",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_git_privacy_closure_requires_private_ignore_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            (paths["root"] / ".gitignore").write_text("", encoding="utf-8")
            subprocess.run(
                ("git", "-C", str(paths["root"]), "add", "--", ".gitignore"),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "PRIVATE_GIT_IGNORE",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_private_write_preflight_requires_staged_ignore_provenance_and_flags(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            ignore = root / ".gitignore"
            ignore.write_bytes(ignore.read_bytes() + b"# unstaged but valid\n")
            self.assert_inventory_error(
                "PRIVATE_GIT_IGNORE_WORKTREE",
                inventory._private_write_preflight,
                evidence_root=root,
                private_paths=(
                    paths["owner_visible"],
                    paths["private_decisions"],
                    paths["private_telemetry"],
                    root / inventory.PRIVATE_LEDGER_BASENAME,
                ),
            )

        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as temporary:
                paths = self.capture_fixture(Path(temporary))
                root = paths["root"]
                subprocess.run(
                    ("git", "-C", str(root), "update-index", flag, ".gitignore"),
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assert_inventory_error(
                    "PRIVATE_GIT_IGNORE_INDEX_FLAGS",
                    inventory._private_write_preflight,
                    evidence_root=root,
                    private_paths=(
                        paths["owner_visible"],
                        paths["private_decisions"],
                        paths["private_telemetry"],
                        root / inventory.PRIVATE_LEDGER_BASENAME,
                    ),
                )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            (root / ".gitignore").write_text("", encoding="utf-8")
            subprocess.run(
                ("git", "-C", str(root), "add", "--", ".gitignore"),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (root / ".git/info/exclude").write_text(
                "*.private.json\n*.private.jsonl\n*.private.csv\n",
                encoding="utf-8",
            )
            self.assert_inventory_error(
                "PRIVATE_GIT_IGNORE_PROVENANCE",
                inventory._private_write_preflight,
                evidence_root=root,
                private_paths=(
                    paths["owner_visible"],
                    paths["private_decisions"],
                    paths["private_telemetry"],
                    root / inventory.PRIVATE_LEDGER_BASENAME,
                ),
            )

    def test_production_private_write_preflight_runs_before_capture_or_template_io(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture_arguments = [
                "capture",
                "--public-heads",
                str(root / inventory.PUBLIC_HEADS_BASENAME),
                "--owner-visible",
                str(root / inventory.OWNER_VISIBLE_BASENAME),
                "--capture-metadata",
                str(root / inventory.CAPTURE_METADATA_BASENAME),
                "--command-log",
                str(root / inventory.COMMAND_LOG_BASENAME),
                "--private-telemetry",
                str(root / inventory.PRIVATE_TELEMETRY_BASENAME),
            ]
            with (
                mock.patch.object(
                    inventory,
                    "_private_write_preflight",
                    side_effect=inventory.InventoryError("PRIVATE_GIT_IGNORE"),
                ) as preflight,
                mock.patch.object(
                    inventory,
                    "GhClient",
                    side_effect=AssertionError("GhClient constructed before preflight"),
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(inventory.main(capture_arguments), 1)
            preflight.assert_called_once()

            private_heads = root / inventory.OWNER_VISIBLE_BASENAME
            private_heads.write_bytes(b"not read because preflight fails\n")
            private_heads.chmod(0o600)
            private_output = root / inventory.PRIVATE_DECISIONS_BASENAME
            with (
                mock.patch.object(
                    inventory,
                    "_private_write_preflight",
                    side_effect=inventory.InventoryError("PRIVATE_GIT_IGNORE"),
                ) as preflight,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    inventory.main(
                        [
                            "decision-template",
                            "--heads",
                            str(private_heads),
                            "--visibility",
                            "PRIVATE",
                            "--output",
                            str(private_output),
                        ]
                    ),
                    1,
                )
            preflight.assert_called_once()
            self.assertFalse(private_output.exists())

        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            private_output = paths["private_decisions"]
            original_atomic_write = inventory._atomic_write
            events: list[str] = []

            def fail_after_private_replace(path, payload, *, private):
                original_atomic_write(path, payload, private=private)
                raise inventory.InventoryError("PRIVATE_WRITE_TEST")

            def preflight(**_kwargs):
                events.append("preflight")

            with (
                mock.patch.object(
                    inventory, "_private_write_preflight", side_effect=preflight
                ),
                mock.patch.object(
                    inventory, "_atomic_write", side_effect=fail_after_private_replace
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    inventory.main(
                        [
                            "decision-template",
                            "--heads",
                            str(paths["owner_visible"]),
                            "--visibility",
                            "PRIVATE",
                            "--output",
                            str(private_output),
                        ]
                    ),
                    1,
                )
            self.assertEqual(events, ["preflight", "preflight"])
            self.assertIn(b'"review_status": "UNRESOLVED"', private_output.read_bytes())

    def test_render_private_postflight_runs_after_failed_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            original_validate_capture = inventory._validate_capture_metadata
            original_atomic_write = inventory._atomic_write
            events: list[str] = []

            def validate_test_capture(value, **kwargs):
                kwargs["_test_profile"] = True
                return original_validate_capture(value, **kwargs)

            def fail_private_ledger(path, payload, *, private):
                original_atomic_write(path, payload, private=private)
                if path.name == inventory.PRIVATE_LEDGER_BASENAME:
                    raise inventory.InventoryError("PRIVATE_WRITE_TEST")

            def preflight(**_kwargs):
                events.append("preflight")

            with (
                mock.patch.object(
                    inventory,
                    "_validate_capture_metadata",
                    side_effect=validate_test_capture,
                ),
                mock.patch.object(
                    inventory,
                    "_supersession_source_payloads",
                    return_value=({}, []),
                ),
                mock.patch.object(
                    inventory, "_private_write_preflight", side_effect=preflight
                ),
                mock.patch.object(
                    inventory, "_atomic_write", side_effect=fail_private_ledger
                ),
            ):
                self.assert_inventory_error(
                    "PRIVATE_WRITE_TEST",
                    inventory.render_files,
                    public_heads=paths["public_heads"],
                    owner_visible=paths["owner_visible"],
                    public_decisions=paths["public_decisions"],
                    private_decisions=paths["private_decisions"],
                    capture_metadata=paths["capture_metadata"],
                    command_log=paths["command_log"],
                    output_root=paths["root"],
                    supersession_audit=paths["supersession_audit"],
                )
            self.assertEqual(events, ["preflight", "preflight"])
            private_ledger = paths["root"] / inventory.PRIVATE_LEDGER_BASENAME
            self.assertTrue(private_ledger.exists())
            self.assertEqual(stat.S_IMODE(private_ledger.stat().st_mode), 0o600)

    def test_production_capture_orchestration_closes_signal_guard_before_postflight(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "public_heads": root / inventory.PUBLIC_HEADS_BASENAME,
                "owner_visible": root / inventory.OWNER_VISIBLE_BASENAME,
                "capture_metadata": root / inventory.CAPTURE_METADATA_BASENAME,
                "command_log": root / inventory.COMMAND_LOG_BASENAME,
                "private_telemetry": root / inventory.PRIVATE_TELEMETRY_BASENAME,
            }
            public_record = rest_repository("sepahead/alpha-public", 1_001)
            private_record = rest_repository(
                PRIVATE_CANARY, 9_001, visibility="private"
            )
            client = FakeRestClient()
            queue_complete_capture(client, public_record, private_record)
            events: list[str] = []

            def construct_client(**_kwargs):
                self.assertIsNone(inventory._GH_SIGNAL_OWNER)
                client._shutdown_requested = False
                inventory._GH_SIGNAL_OWNER = client
                events.append("client-open")

                def close() -> None:
                    self.assertIsNotNone(inventory._GH_SIGNAL_OWNER)
                    inventory._GH_SIGNAL_OWNER = None
                    events.append("client-close")

                client.close = close
                return client

            def preflight(**_kwargs):
                self.assertIsNone(inventory._GH_SIGNAL_OWNER)
                events.append("preflight")

            profile = dict(inventory.PRODUCTION_CLOSURE_PROFILE)
            profile.update(
                {
                    "expected_owner_visible_repositories": 2,
                    "expected_private_repositories": 1,
                    "expected_public_repositories": 1,
                }
            )
            with (
                mock.patch.object(inventory, "PRODUCTION_CLOSURE_PROFILE", profile),
                mock.patch.object(
                    inventory, "_PRODUCTION_CAPTURE_CLIENT_TYPE", FakeRestClient
                ),
                mock.patch.object(inventory, "GhClient", side_effect=construct_client),
                mock.patch.object(
                    inventory, "_private_write_preflight", side_effect=preflight
                ),
            ):
                result = inventory.capture_production_files(
                    **paths,
                    minimum_remaining=100,
                    maximum_pages=10,
                    head_workers=1,
                    timeout_seconds=60,
                )
            self.assertEqual(result, {"owner_visible": 2, "private": 1, "public": 1})
            self.assertEqual(
                events,
                ["preflight", "client-open", "client-close", "preflight"],
            )
            self.assertIsNone(inventory._GH_SIGNAL_OWNER)
            client.assert_consumed()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = FakeRestClient()
            self.assert_inventory_error(
                "CAPTURE_ORCHESTRATION_REQUIRED",
                inventory.capture_files,
                client=client,
                owner_name=inventory.OWNER,
                public_heads=root / inventory.PUBLIC_HEADS_BASENAME,
                owner_visible=root / inventory.OWNER_VISIBLE_BASENAME,
                capture_metadata=root / inventory.CAPTURE_METADATA_BASENAME,
                command_log=root / inventory.COMMAND_LOG_BASENAME,
                private_telemetry=root / inventory.PRIVATE_TELEMETRY_BASENAME,
                minimum_remaining=100,
                maximum_pages=10,
                expected_public_repositories=(
                    inventory.PRODUCTION_CLOSURE_PROFILE["expected_public_repositories"]
                ),
                expected_private_repositories=(
                    inventory.PRODUCTION_CLOSURE_PROFILE[
                        "expected_private_repositories"
                    ]
                ),
            )
            self.assertEqual(client.calls, [])
            self.assert_inventory_error(
                "CAPTURE_ORCHESTRATION_REQUIRED",
                inventory.capture_files,
                client=client,
                owner_name=inventory.OWNER,
                public_heads=root / inventory.PUBLIC_HEADS_BASENAME,
                owner_visible=root / inventory.OWNER_VISIBLE_BASENAME,
                capture_metadata=root / inventory.CAPTURE_METADATA_BASENAME,
                command_log=root / inventory.COMMAND_LOG_BASENAME,
                private_telemetry=root / inventory.PRIVATE_TELEMETRY_BASENAME,
                minimum_remaining=100,
                maximum_pages=10,
                expected_public_repositories=(
                    inventory.PRODUCTION_CLOSURE_PROFILE["expected_public_repositories"]
                ),
                expected_private_repositories=(
                    inventory.PRODUCTION_CLOSURE_PROFILE[
                        "expected_private_repositories"
                    ]
                ),
                _orchestration_token=(
                    inventory._PRODUCTION_CAPTURE_ORCHESTRATION_TOKEN
                ),
            )
            self.assertEqual(client.calls, [])

    def test_production_capture_postflight_runs_when_client_close_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "public_heads": root / inventory.PUBLIC_HEADS_BASENAME,
                "owner_visible": root / inventory.OWNER_VISIBLE_BASENAME,
                "capture_metadata": root / inventory.CAPTURE_METADATA_BASENAME,
                "command_log": root / inventory.COMMAND_LOG_BASENAME,
                "private_telemetry": root / inventory.PRIVATE_TELEMETRY_BASENAME,
            }
            public_record = rest_repository("sepahead/alpha-public", 1_001)
            private_record = rest_repository(
                PRIVATE_CANARY, 9_001, visibility="private"
            )
            client = FakeRestClient()
            queue_complete_capture(client, public_record, private_record)
            events: list[str] = []

            def construct_client(**_kwargs):
                self.assertIsNone(inventory._GH_SIGNAL_OWNER)
                client._shutdown_requested = False
                inventory._GH_SIGNAL_OWNER = client
                events.append("client-open")

                def close() -> None:
                    self.assertIsNotNone(inventory._GH_SIGNAL_OWNER)
                    inventory._GH_SIGNAL_OWNER = None
                    events.append("client-close-failed")
                    raise inventory.InventoryError("CLIENT_CLOSE_TEST")

                client.close = close
                return client

            def preflight(**_kwargs):
                self.assertIsNone(inventory._GH_SIGNAL_OWNER)
                events.append("preflight")

            profile = dict(inventory.PRODUCTION_CLOSURE_PROFILE)
            profile.update(
                {
                    "expected_owner_visible_repositories": 2,
                    "expected_private_repositories": 1,
                    "expected_public_repositories": 1,
                }
            )
            with (
                mock.patch.object(inventory, "PRODUCTION_CLOSURE_PROFILE", profile),
                mock.patch.object(
                    inventory, "_PRODUCTION_CAPTURE_CLIENT_TYPE", FakeRestClient
                ),
                mock.patch.object(inventory, "GhClient", side_effect=construct_client),
                mock.patch.object(
                    inventory, "_private_write_preflight", side_effect=preflight
                ),
            ):
                self.assert_inventory_error(
                    "CLIENT_CLOSE_TEST",
                    inventory.capture_production_files,
                    **paths,
                    minimum_remaining=100,
                    maximum_pages=10,
                    head_workers=1,
                    timeout_seconds=60,
                )
            self.assertEqual(
                events,
                ["preflight", "client-open", "client-close-failed", "preflight"],
            )
            self.assertIsNone(inventory._GH_SIGNAL_OWNER)
            client.assert_consumed()

    def test_required_evidence_and_audit_index_modes_are_non_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            public_heads = paths["public_heads"]
            public_heads.chmod(0o755)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", public_heads.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "GIT_REQUIRED_STAGED_MODE",
                inventory.check_files,
                root=root,
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )
            public_heads.chmod(0o644)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", public_heads.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            audit = root / inventory.AUDIT_METADATA_BASENAME
            audit.chmod(0o755)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", audit.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "GIT_AUDIT_MODE",
                inventory.check_files,
                root=root,
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )
            audit.chmod(0o644)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", audit.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            ignore = root / ".gitignore"
            ignore.chmod(0o755)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", ignore.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "PRIVATE_GIT_IGNORE_INDEX_MODE",
                inventory.check_files,
                root=root,
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_owner_check_requires_audit_staged_last_and_exact_required_blobs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            audit = root / inventory.AUDIT_METADATA_BASENAME
            subprocess.run(
                ("git", "-C", str(root), "rm", "--cached", "--", audit.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "GIT_AUDIT_STAGE",
                inventory.check_files,
                root=root,
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )
            subprocess.run(
                ("git", "-C", str(root), "add", "--", audit.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            bound = root / "bound-source.md"
            bound.write_bytes(b"indexed source A\n")
            subprocess.run(
                ("git", "-C", str(root), "add", "--", bound.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            arguments = self.closure_kwargs(paths, audit_payload=audit.read_bytes())
            arguments["required_staged_payloads"][bound] = b"expected source B\n"
            self.assert_inventory_error(
                "GIT_REQUIRED_STAGED_OUTPUT",
                inventory._git_privacy_closure,
                **arguments,
            )

    def test_production_artifact_contract_binds_exact_generated_diagram(self) -> None:
        project_root = MODULE_PATH.resolve(strict=True).parent.parent
        production_artifacts = inventory._production_maintained_artifact_payloads()
        diagram = project_root / "docs/assets" / inventory.ECOSYSTEM_DIAGRAM_BASENAME
        self.assertEqual(
            production_artifacts,
            {
                MODULE_PATH.resolve(strict=True): MODULE_PATH.read_bytes(),
                diagram: inventory.ecosystem_source_inventory_svg(),
            },
        )
        with tempfile.TemporaryDirectory(
            prefix="inventory-copy-", dir=project_root
        ) as temporary:
            copied = Path(temporary) / "ecosystem_source_inventory.py"
            copied.write_bytes(MODULE_PATH.read_bytes())
            copied.chmod(0o644)
            self.assert_inventory_error(
                "INVENTORY_SCRIPT_LOCATION",
                inventory._canonical_inventory_location,
                copied,
            )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            audit = root / inventory.AUDIT_METADATA_BASENAME
            staged_diagram = root / "docs/assets" / inventory.ECOSYSTEM_DIAGRAM_BASENAME
            staged_diagram.parent.mkdir(parents=True, exist_ok=True)
            expected = inventory.ecosystem_source_inventory_svg()
            staged_diagram.write_bytes(expected)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", staged_diagram.relative_to(root)),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            arguments = self.closure_kwargs(paths, audit_payload=audit.read_bytes())
            arguments["required_staged_payloads"][staged_diagram] = expected
            receipt, state = inventory._git_privacy_closure(**arguments)
            self.assertEqual(receipt["result"], "PASS")
            self.assertEqual(state, "AUDIT_STAGED_FINAL")

            staged_diagram.write_bytes(b"<svg/>\n")
            subprocess.run(
                ("git", "-C", str(root), "add", "--", staged_diagram.relative_to(root)),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "GIT_REQUIRED_STAGED_OUTPUT",
                inventory._git_privacy_closure,
                **arguments,
            )

            staged_diagram.write_bytes(expected)
            staged_diagram.chmod(0o755)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", staged_diagram.relative_to(root)),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "GIT_REQUIRED_STAGED_MODE",
                inventory._git_privacy_closure,
                **arguments,
            )

            staged_diagram.chmod(0o644)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", staged_diagram.relative_to(root)),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                (
                    "git",
                    "-C",
                    str(root),
                    "rm",
                    "--cached",
                    "--",
                    staged_diagram.relative_to(root),
                ),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            staged_diagram.unlink()
            self.assert_inventory_error(
                "GIT_REQUIRED_STAGED_OUTPUT",
                inventory._git_privacy_closure,
                **arguments,
            )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            audit = root / inventory.AUDIT_METADATA_BASENAME
            tool = root / "tools/ecosystem_source_inventory.py"
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool_payload = b"# bound inventory source\n"
            tool.write_bytes(tool_payload)
            subprocess.run(
                ("git", "-C", str(root), "add", "--", tool.relative_to(root)),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            arguments = self.closure_kwargs(paths, audit_payload=audit.read_bytes())
            arguments["required_staged_payloads"][tool] = tool_payload
            receipt, state = inventory._git_privacy_closure(**arguments)
            self.assertEqual(receipt["result"], "PASS")
            self.assertEqual(state, "AUDIT_STAGED_FINAL")

            ignore = root / ".gitignore"
            ignore.write_bytes(
                ignore.read_bytes() + b"tools/ecosystem_source_inventory.py\n"
            )
            subprocess.run(
                ("git", "-C", str(root), "add", "--", ignore.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                (
                    "git",
                    "-C",
                    str(root),
                    "rm",
                    "--cached",
                    "--",
                    tool.relative_to(root),
                ),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "GIT_REQUIRED_STAGED_OUTPUT",
                inventory._git_privacy_closure,
                **arguments,
            )

    def test_git_privacy_closure_rejects_tracked_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            link = paths["root"] / "tracked-link"
            link.symlink_to("repository-heads.jsonl")
            subprocess.run(
                ("git", "-C", str(paths["root"]), "add", "--", link.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assert_inventory_error(
                "GIT_INDEX_ENTRY",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_git_privacy_closure_enforces_file_and_aggregate_bounds(self) -> None:
        for constant, value, code in (
            ("MAX_TRACKED_FILE_BYTES", 1, "GIT_BLOB_FILE_BOUND"),
            ("MAX_TRACKED_SCAN_BYTES", 1, "GIT_BLOB_AGGREGATE_BOUND"),
        ):
            with (
                self.subTest(constant=constant),
                tempfile.TemporaryDirectory() as temporary,
            ):
                paths = self.capture_fixture(Path(temporary))
                with mock.patch.object(inventory, constant, value):
                    self.assert_inventory_error(
                        code,
                        inventory._git_privacy_closure,
                        **self.closure_kwargs(paths),
                    )

    def test_git_privacy_receipt_is_bounded_and_public_check_is_commitment_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            audit, audit_payload = inventory._load_json(
                paths["root"] / inventory.AUDIT_METADATA_BASENAME
            )
            scan = audit["private_evidence"]["cross_lane_scan"]
            self.assertEqual(
                set(scan),
                {
                    "result",
                    "scan_configuration_sha256",
                    "sealed_index_sha256",
                    "tracked_bytes",
                    "tracked_files",
                },
            )
            self.assertEqual(scan["result"], "PASS")
            self.assertGreater(scan["tracked_files"], 0)
            self.assertGreater(scan["tracked_bytes"], 0)
            self.assertNotIn(PRIVATE_CANARY.encode("ascii"), audit_payload)
            with mock.patch.object(
                inventory,
                "_git_privacy_closure",
                side_effect=AssertionError("public check invoked owner-local scan"),
            ):
                result = inventory.check_files(
                    root=paths["root"],
                    owner_visible=None,
                    private_decisions=None,
                    _test_profile=True,
                )
            self.assertEqual(result["private_scope"], "COMMITMENT_ONLY")

    def test_git_boundary_disables_lazy_fetch_and_replace_objects(self) -> None:
        environment = inventory._git_environment("/safe/bin")
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        with mock.patch.object(
            inventory,
            "_run_bounded_process",
            return_value=(b"", 0),
        ) as bounded:
            inventory._git_run(
                Path("/safe/bin/git"),
                Path("/repository"),
                ("status", "--porcelain"),
                environment=environment,
            )
        positional = bounded.call_args.args
        keyword = bounded.call_args.kwargs
        self.assertEqual(positional[0], Path("/safe/bin/git"))
        self.assertEqual(
            positional[1],
            (
                "--no-replace-objects",
                "-C",
                "/repository",
                "status",
                "--porcelain",
            ),
        )
        self.assertEqual(keyword["environment"]["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(keyword["environment"]["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_git_replace_ref_cannot_substitute_scanned_index_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            safe_oid = (
                subprocess.run(
                    (
                        "git",
                        "-C",
                        str(root),
                        "rev-parse",
                        f":{inventory.PUBLIC_HEADS_BASENAME}",
                    ),
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                .stdout.decode("ascii")
                .strip()
            )
            private_oid = (
                subprocess.run(
                    ("git", "-C", str(root), "hash-object", "-w", "--stdin"),
                    input=PRIVATE_CANARY.encode("utf-8"),
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                .stdout.decode("ascii")
                .strip()
            )
            subprocess.run(
                ("git", "-C", str(root), "replace", safe_oid, private_oid),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            replaced = subprocess.run(
                ("git", "-C", str(root), "cat-file", "-p", safe_oid),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).stdout
            self.assertEqual(replaced, PRIVATE_CANARY.encode("utf-8"))
            verified = inventory.check_files(
                root=root,
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )
            self.assertEqual(verified["seal_state"], "AUDIT_STAGED_FINAL")

    def test_sealed_index_digest_changes_with_staged_public_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            root = paths["root"]
            audit_path = root / inventory.AUDIT_METADATA_BASENAME
            audit, audit_payload = inventory._load_json(audit_path)
            original_digest = audit["private_evidence"]["cross_lane_scan"][
                "sealed_index_sha256"
            ]
            ignore = root / ".gitignore"
            ignore.write_bytes(ignore.read_bytes() + b"# receipt-bound comment\n")
            subprocess.run(
                ("git", "-C", str(root), "add", "--", ignore.name),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            receipt, state = inventory._git_privacy_closure(
                **self.closure_kwargs(paths, audit_payload=audit_payload)
            )
            self.assertEqual(state, "AUDIT_STAGED_FINAL")
            self.assertNotEqual(receipt["sealed_index_sha256"], original_digest)
            self.assert_inventory_error(
                "PRIVATE_GIT_SCAN_DRIFT",
                inventory.check_files,
                root=root,
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_private_layout_rejects_wrong_root_basename_symlink_and_hardlink(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            wrong = paths["root"] / "wrong.private.json"
            self.assert_inventory_error(
                "EVIDENCE_LAYOUT",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=wrong,
                _test_profile=True,
            )
            sibling = paths["root"] / "sibling"
            sibling.mkdir()
            sibling_decisions = sibling / inventory.PRIVATE_DECISIONS_BASENAME
            os.link(paths["private_decisions"], sibling_decisions)
            self.assert_inventory_error(
                "EVIDENCE_LAYOUT",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=sibling_decisions,
                _test_profile=True,
            )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            hardlink = paths["root"] / "private-hardlink-backup"
            os.link(paths["private_decisions"], hardlink)
            self.assert_inventory_error(
                "PRIVATE_MODE",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            original = paths["root"] / "private-decisions-original"
            paths["private_decisions"].rename(original)
            paths["private_decisions"].symlink_to(original)
            self.assert_inventory_error(
                "PRIVATE_MODE",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_bounded_reader_rejects_path_replacement_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / inventory.PRIVATE_DECISIONS_BASENAME
            path.write_bytes(b"private evidence bytes")
            path.chmod(0o600)
            backup = root / "opened-original"
            original_read = os.read
            replaced = False

            def replacing_read(descriptor: int, count: int) -> bytes:
                nonlocal replaced
                chunk = original_read(descriptor, count)
                if chunk and not replaced:
                    replaced = True
                    path.rename(backup)
                    path.write_bytes(b"private evidence bytes")
                    path.chmod(0o600)
                return chunk

            with mock.patch.object(inventory.os, "read", side_effect=replacing_read):
                self.assert_inventory_error(
                    "PRIVATE_READ_RACE",
                    inventory._read_bounded,
                    path,
                    1024,
                    "PRIVATE_READ_RACE",
                    required_mode=0o600,
                )

    def test_bounded_reader_rejects_same_inode_mutate_restore_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / inventory.PRIVATE_DECISIONS_BASENAME
            original_payload = b"private evidence bytes"
            path.write_bytes(original_payload)
            path.chmod(0o600)
            original_metadata = path.stat()
            original_read = os.read
            mutated = False

            def mutating_read(descriptor: int, count: int) -> bytes:
                nonlocal mutated
                chunk = original_read(descriptor, count)
                if chunk and not mutated:
                    mutated = True
                    path.write_bytes(b"PRIVATE EVIDENCE BYTES")
                    path.write_bytes(original_payload)
                    os.utime(
                        path,
                        ns=(
                            original_metadata.st_atime_ns,
                            original_metadata.st_mtime_ns,
                        ),
                    )
                    self.assertEqual(path.stat().st_ino, original_metadata.st_ino)
                    self.assertEqual(path.stat().st_size, original_metadata.st_size)
                    self.assertEqual(
                        path.stat().st_mtime_ns, original_metadata.st_mtime_ns
                    )
                return chunk

            with mock.patch.object(inventory.os, "read", side_effect=mutating_read):
                self.assert_inventory_error(
                    "PRIVATE_READ_RACE",
                    inventory._read_bounded,
                    path,
                    1024,
                    "PRIVATE_READ_RACE",
                    required_mode=0o600,
                )

    def test_argument_errors_do_not_reflect_private_values(self) -> None:
        private_argument = "--" + PRIVATE_CANARY.replace("/", "-")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = inventory.main([private_argument])
        self.assertEqual(result, 1)
        emitted = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(PRIVATE_CANARY, emitted)
        self.assertNotIn(private_argument, emitted)
        self.assertIn("ERROR ARGUMENTS", emitted)

    def test_capture_cli_has_no_arbitrary_gh_executable_option(self) -> None:
        self.assert_inventory_error(
            "ARGUMENTS",
            inventory._parser().parse_args,
            ["capture", "--gh", "/tmp/substitute-gh"],
        )

    def test_public_generated_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            classification = paths["root"] / "repository-classification.csv"
            classification.write_bytes(classification.read_bytes() + b"drift\n")
            self.assert_inventory_error(
                "GENERATED_DRIFT",
                inventory.check_files,
                root=paths["root"],
                owner_visible=None,
                private_decisions=None,
                _test_profile=True,
            )

    def test_capture_metadata_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            value, _payload = inventory._load_json(paths["capture_metadata"])
            value["capture"]["tool_api_request_contract"][
                "tool_semantics_independently_verified"
            ] = True
            inventory._atomic_write(
                paths["capture_metadata"],
                inventory.canonical_json(value),
                private=False,
            )
            self.assert_inventory_error(
                "CAPTURE_TOOL_REQUEST_CONTRACT",
                inventory.check_files,
                root=paths["root"],
                owner_visible=None,
                private_decisions=None,
                _test_profile=True,
            )

    def test_capture_requires_exact_operator_repository_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "public_heads": root / inventory.PUBLIC_HEADS_BASENAME,
                "owner_visible": root / inventory.OWNER_VISIBLE_BASENAME,
                "capture_metadata": root / inventory.CAPTURE_METADATA_BASENAME,
                "command_log": root / inventory.COMMAND_LOG_BASENAME,
                "private_telemetry": root / inventory.PRIVATE_TELEMETRY_BASENAME,
            }
            for value, code in (
                (True, "EXPECTED_PUBLIC_REPOSITORIES"),
                (1.0, "EXPECTED_PUBLIC_REPOSITORIES"),
            ):
                with self.subTest(value=value):
                    self.assert_inventory_error(
                        code,
                        inventory.capture_files,
                        client=FakeRestClient(),
                        owner_name="sepahead",
                        minimum_remaining=100,
                        maximum_pages=10,
                        expected_public_repositories=value,
                        expected_private_repositories=0,
                        **paths,
                    )

            public_record = rest_repository("sepahead/a", 1)
            private_record = rest_repository(PRIVATE_CANARY, 9, visibility="private")
            client = FakeRestClient()
            queue_complete_capture(client, public_record, private_record)
            self.assert_inventory_error(
                "CLOSURE_PROFILE_MISMATCH",
                inventory.capture_files,
                client=client,
                owner_name="sepahead",
                minimum_remaining=100,
                maximum_pages=10,
                expected_public_repositories=2,
                expected_private_repositories=1,
                _test_profile=True,
                **paths,
            )
            self.assertFalse(any(path.exists() for path in paths.values()))

    def test_capture_reverifies_the_same_owner_identity_at_end(self) -> None:
        public_record = rest_repository("sepahead/a", 1)
        private_record = rest_repository(PRIVATE_CANARY, 9, visibility="private")
        client = FakeRestClient()
        queue_complete_capture(client, public_record, private_record)
        changed = identity_payload(account_id=OWNER["account_id"] + 1)
        changed["node_id"] = "different-owner-node"
        client.responses["/users/sepahead"][1] = (changed, copy.deepcopy(RATE))
        client.responses["/user"][1] = (changed, copy.deepcopy(RATE))
        self.assert_inventory_error(
            "FINAL_IDENTITY_MISMATCH",
            inventory.capture_account,
            client,
            owner_name="sepahead",
            minimum_remaining=100,
            maximum_pages=10,
        )

    def test_capture_rejects_inventory_script_drift_before_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "public_heads": root / inventory.PUBLIC_HEADS_BASENAME,
                "owner_visible": root / inventory.OWNER_VISIBLE_BASENAME,
                "capture_metadata": root / inventory.CAPTURE_METADATA_BASENAME,
                "command_log": root / inventory.COMMAND_LOG_BASENAME,
                "private_telemetry": root / inventory.PRIVATE_TELEMETRY_BASENAME,
            }
            public_record = rest_repository("sepahead/a", 1)
            private_record = rest_repository(PRIVATE_CANARY, 9, visibility="private")
            client = FakeRestClient()
            queue_complete_capture(client, public_record, private_record)
            first = inventory._file_record(
                "ecosystem_source_inventory.py",
                b"first",
                classification="PUBLIC_TOOL_SOURCE",
            )
            second = inventory._file_record(
                "ecosystem_source_inventory.py",
                b"second",
                classification="PUBLIC_TOOL_SOURCE",
            )
            with mock.patch.object(
                inventory, "_inventory_script_record", side_effect=(first, second)
            ):
                self.assert_inventory_error(
                    "INVENTORY_SCRIPT_DRIFT",
                    inventory.capture_files,
                    client=client,
                    owner_name="sepahead",
                    minimum_remaining=100,
                    maximum_pages=10,
                    expected_public_repositories=1,
                    expected_private_repositories=1,
                    _test_profile=True,
                    **paths,
                )
            self.assertFalse(any(path.exists() for path in paths.values()))

    def test_capture_binds_runtime_invocation_and_four_identity_gets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            metadata, _payload = inventory._load_json(paths["capture_metadata"])
            capture = metadata["capture"]
            self.assertEqual(
                capture["expected_repository_counts"], {"private": 1, "public": 1}
            )
            self.assertNotIn("identity_requests", capture)
            self.assertNotIn("identity_rate_limit", capture)
            private_telemetry, _private_telemetry_payload = inventory._load_json(
                paths["private_telemetry"], private=True
            )
            self.assertEqual(private_telemetry["identity_summary"]["requests"], 4)
            self.assertEqual(capture["output_labels"], inventory.CAPTURE_OUTPUT_LABELS)
            self.assertEqual(
                capture["credential_binding"], inventory.CREDENTIAL_BINDING
            )
            self.assertEqual(
                capture["tool_api_request_contract"],
                inventory.TOOL_API_REQUEST_CONTRACT,
            )
            self.assertFalse(
                capture["tool_api_request_contract"][
                    "tool_semantics_independently_verified"
                ]
            )
            self.assertNotIn("provider", capture)
            self.assertNotIn("mutation_performed", capture)
            self.assertEqual(
                capture["invocation_sha256"],
                inventory.sha256(
                    inventory.canonical_json(
                        inventory._capture_invocation_document(capture)
                    )
                ),
            )
            command_raw, _command_payload = inventory._load_jsonl(paths["command_log"])
            self.assertTrue(
                all(
                    item["invocation_sha256"] == capture["invocation_sha256"]
                    for item in command_raw
                )
            )
            public_raw, public_payload = inventory._load_jsonl(paths["public_heads"])
            owner_raw, owner_payload = inventory._load_jsonl(
                paths["owner_visible"], private=True
            )
            del public_raw
            _unused, command_payload = inventory._load_jsonl(paths["command_log"])
            validated_capture = inventory._validate_capture_metadata(
                metadata,
                public_payload=public_payload,
                owner_payload=owner_payload,
                command_payload=command_payload,
                owner_records=owner_raw,
                _test_profile=True,
            )
            mutant = copy.deepcopy(command_raw)
            mutant[0]["invocation_sha256"] = "b" * 64
            self.assert_inventory_error(
                "COMMAND_CAPTURE_BINDING",
                inventory._bind_command_log_to_capture,
                inventory._command_log(mutant),
                validated_capture,
            )

    def test_capture_and_command_chronology_use_rfc3339_instants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            metadata, _metadata_payload = inventory._load_json(
                paths["capture_metadata"]
            )
            public_raw, public_payload = inventory._load_jsonl(paths["public_heads"])
            owner_raw, owner_payload = inventory._load_jsonl(
                paths["owner_visible"], private=True
            )
            del public_raw
            command_raw, command_payload = inventory._load_jsonl(paths["command_log"])

            reverse = copy.deepcopy(metadata)
            reverse["capture"]["started_at_utc"] = "2026-08-02T00:00:00.100001Z"
            reverse["capture"]["completed_at_utc"] = "2026-08-02T00:00:00.1Z"
            self.assert_inventory_error(
                "CAPTURE_TIME_ORDER",
                inventory._validate_capture_metadata,
                reverse,
                public_payload=public_payload,
                owner_payload=owner_payload,
                command_payload=command_payload,
                owner_records=owner_raw,
                _test_profile=True,
            )

            equal = copy.deepcopy(metadata)
            equal["capture"]["started_at_utc"] = "2026-08-02T00:00:00.1Z"
            equal["capture"]["completed_at_utc"] = "2026-08-02T00:00:00.100000Z"
            inventory._validate_capture_metadata(
                equal,
                public_payload=public_payload,
                owner_payload=owner_payload,
                command_payload=command_payload,
                owner_records=owner_raw,
                _test_profile=True,
            )

            reverse_commands = copy.deepcopy(command_raw)
            reverse_commands[0]["started_at_utc"] = "2026-08-02T00:00:00.100001Z"
            reverse_commands[0]["completed_at_utc"] = "2026-08-02T00:00:00.1Z"
            self.assert_inventory_error(
                "COMMAND_TIME_ORDER", inventory._command_log, reverse_commands
            )
            equal_commands = copy.deepcopy(command_raw)
            equal_commands[0]["started_at_utc"] = "2026-08-02T00:00:00.1Z"
            equal_commands[0]["completed_at_utc"] = "2026-08-02T00:00:00.100000Z"
            inventory._command_log(equal_commands)

    def test_command_and_metadata_json_number_aliases_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            commands, _payload = inventory._load_jsonl(paths["command_log"])
            for field, value, code in (
                ("sequence", True, "COMMAND_RECORD"),
                ("pass", 1.0, "COMMAND_RECORD"),
                ("rows", False, "COMMAND_ROWS"),
                ("private_identifiers_logged", 0, "COMMAND_RECORD"),
            ):
                mutant = copy.deepcopy(commands)
                mutant[0][field] = value
                with self.subTest(field=field, value=value):
                    self.assert_inventory_error(code, inventory._command_log, mutant)
            self.assert_inventory_error(
                "COMMAND_COUNT", inventory._command_log, commands + [commands[-1]]
            )

            metadata, _payload = inventory._load_json(paths["capture_metadata"])
            mutants = (
                ("authority", "archive_authorized", 0, "CAPTURE_METADATA_SCHEMA"),
                ("capture", "maximum_get_attempts", 3.0, "CAPTURE_GET_ATTEMPTS"),
                ("capture", "request_timeout_seconds", True, "CAPTURE_REQUEST_TIMEOUT"),
                (
                    "capture",
                    "invocation_sha256",
                    int("1" * 64),
                    "CAPTURE_INVOCATION_DIGEST",
                ),
            )
            public_raw, public_payload = inventory._load_jsonl(paths["public_heads"])
            owner_raw, owner_payload = inventory._load_jsonl(
                paths["owner_visible"], private=True
            )
            del public_raw
            _commands, command_payload = inventory._load_jsonl(paths["command_log"])
            for section, field, value, code in mutants:
                mutant = copy.deepcopy(metadata)
                mutant[section][field] = value
                with self.subTest(section=section, field=field):
                    self.assert_inventory_error(
                        code,
                        inventory._validate_capture_metadata,
                        mutant,
                        public_payload=public_payload,
                        owner_payload=owner_payload,
                        command_payload=command_payload,
                        owner_records=owner_raw,
                        _test_profile=True,
                    )
            invocation_mutants = []
            maximum_pages = copy.deepcopy(metadata)
            maximum_pages["capture"]["maximum_pages"] = 9
            invocation_mutants.append(maximum_pages)
            timeout = copy.deepcopy(metadata)
            timeout["capture"]["request_timeout_seconds"] = 59
            invocation_mutants.append(timeout)
            workers = copy.deepcopy(metadata)
            workers["capture"]["maximum_head_workers"] = 2
            invocation_mutants.append(workers)
            reserve = copy.deepcopy(metadata)
            reserve["capture"]["minimum_rate_reserve"] = 99
            invocation_mutants.append(reserve)
            runtime = copy.deepcopy(metadata)
            runtime["capture"]["python_runtime"]["implementation"] = "OtherPython"
            invocation_mutants.append(runtime)
            for mutant in invocation_mutants:
                self.assert_inventory_error(
                    "CAPTURE_INVOCATION_BINDING",
                    inventory._validate_capture_metadata,
                    mutant,
                    public_payload=public_payload,
                    owner_payload=owner_payload,
                    command_payload=command_payload,
                    owner_records=owner_raw,
                    _test_profile=True,
                )

    def test_audit_json_number_aliases_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            audit_path = paths["root"] / inventory.AUDIT_METADATA_BASENAME
            original, _payload = inventory._load_json(audit_path)
            mutants = (
                (("authority", "archive_authorized"), 0, "AUDIT_SCHEMA"),
                (("public_evidence", "unresolved"), False, "AUDIT_PUBLIC"),
                (("private_evidence", "repositories"), False, "AUDIT_PRIVATE"),
                (
                    ("private_evidence", "commitment_sha256"),
                    int("1" * 64),
                    "AUDIT_PRIVATE",
                ),
            )
            for keys, value, code in mutants:
                mutant = copy.deepcopy(original)
                mutant[keys[0]][keys[1]] = value
                with self.subTest(keys=keys):
                    self.assert_inventory_error(
                        code,
                        inventory._validate_audit_document,
                        mutant,
                        _test_profile=True,
                    )

            scan_alias = copy.deepcopy(original)
            scan_alias["private_evidence"]["cross_lane_scan"]["tracked_files"] = False
            self.assert_inventory_error(
                "AUDIT_PRIVATE_SCAN",
                inventory._validate_audit_document,
                scan_alias,
                _test_profile=True,
            )

            capture_alias = copy.deepcopy(original)
            capture_alias["capture"]["stable_tool_results_across_two_passes"] = 0
            inventory._atomic_write(
                audit_path,
                inventory.canonical_json(capture_alias),
                private=False,
            )
            self.assert_inventory_error(
                "AUDIT_CAPTURE_BINDING",
                inventory.check_files,
                root=paths["root"],
                owner_visible=None,
                private_decisions=None,
                _test_profile=True,
            )

    def test_supersession_schema_is_exact_and_release_inert(self) -> None:
        valid = valid_supersession()
        self.assertIs(inventory.validate_supersession_audit(valid), valid)
        self.assertEqual(valid["prepared_by"], "Codex automated draft")
        self.assertEqual(valid["review_kind"], "AUTOMATED_FACTUAL_REVIEW")
        self.assertEqual(valid["review_status"], "REVIEWED")
        self.assertEqual(valid["reviewer"], "Codex automated factual review")
        self.assertEqual(valid["review_date"], inventory.SUPERSESSION_REVIEW_DATE)
        self.assertEqual(
            valid["review_attestation"], inventory.SUPERSESSION_REVIEW_ATTESTATION
        )
        self.assertIs(valid["owner_approval_established"], False)
        self.assertIs(valid["reviewer_identity_authenticated"], False)
        inventory._require_reviewed_supersession(valid)
        draft = copy.deepcopy(inventory.SUPERSESSION_UNREVIEWED_DOCUMENT)
        self.assertIs(inventory.validate_supersession_audit(draft), draft)
        self.assert_inventory_error(
            "SUPERSESSION_UNREVIEWED",
            inventory._require_reviewed_supersession,
            draft,
        )
        mutants = []
        missing = copy.deepcopy(valid)
        missing.pop("authority")
        mutants.append((missing, "SUPERSESSION_KEYS"))
        release_field = copy.deepcopy(valid)
        release_field["release_authorized"] = True
        mutants.append((release_field, "SUPERSESSION_KEYS"))
        authority_alias = copy.deepcopy(valid)
        authority_alias["authority"]["release_authorized"] = 0
        mutants.append((authority_alias, "SUPERSESSION_AUTHORITY"))
        duplicate_source = copy.deepcopy(valid)
        duplicate_source["sources"][1] = copy.deepcopy(duplicate_source["sources"][0])
        mutants.append((duplicate_source, "SUPERSESSION_SOURCE"))
        traversal = copy.deepcopy(valid)
        traversal["sources"][0]["path"] = "../docs/ROADMAP-STATUS.md"
        mutants.append((traversal, "SUPERSESSION_SOURCE"))
        wrong_disposition = copy.deepcopy(valid)
        wrong_disposition["decisions"][0]["disposition"] = "INVENTORY_ONLY"
        mutants.append((wrong_disposition, "SUPERSESSION_DECISION"))
        empty_implication = copy.deepcopy(valid)
        empty_implication["decisions"][0]["must_not_imply"] = []
        mutants.append((empty_implication, "SUPERSESSION_MUST_NOT_IMPLY"))
        unresolved = copy.deepcopy(valid)
        unresolved["unresolved"] = []
        mutants.append((unresolved, "SUPERSESSION_UNRESOLVED"))
        false_human_review = copy.deepcopy(valid)
        false_human_review["reviewer"] = "Unverified Human"
        mutants.append((false_human_review, "SUPERSESSION_REVIEW_STATUS"))
        false_owner_approval = copy.deepcopy(valid)
        false_owner_approval["owner_approval_established"] = True
        mutants.append((false_owner_approval, "SUPERSESSION_REVIEW_STATUS"))
        false_authentication = copy.deepcopy(valid)
        false_authentication["reviewer_identity_authenticated"] = True
        mutants.append((false_authentication, "SUPERSESSION_REVIEW_STATUS"))
        missing_attestation = copy.deepcopy(valid)
        missing_attestation["review_attestation"] = None
        mutants.append((missing_attestation, "SUPERSESSION_REVIEW_STATUS"))
        mixed_draft = copy.deepcopy(valid)
        mixed_draft["review_status"] = "UNREVIEWED"
        mutants.append((mixed_draft, "SUPERSESSION_REVIEW_STATUS"))
        for mutant, code in mutants:
            with self.subTest(code=code):
                self.assert_inventory_error(
                    code, inventory.validate_supersession_audit, mutant
                )

    def test_production_seal_rejects_unreviewed_supersession_draft(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            inventory._atomic_write(
                paths["supersession_audit"],
                inventory.canonical_json(inventory.SUPERSESSION_UNREVIEWED_DOCUMENT),
                private=False,
            )
            with mock.patch.object(inventory, "_private_write_preflight"):
                self.assert_inventory_error(
                    "SUPERSESSION_UNREVIEWED",
                    inventory.render_files,
                    public_heads=paths["public_heads"],
                    owner_visible=paths["owner_visible"],
                    public_decisions=paths["public_decisions"],
                    private_decisions=paths["private_decisions"],
                    capture_metadata=paths["capture_metadata"],
                    command_log=paths["command_log"],
                    output_root=paths["root"],
                    supersession_audit=paths["supersession_audit"],
                    _seal=True,
                )
            self.assert_inventory_error(
                "SUPERSESSION_UNREVIEWED",
                inventory.check_files,
                root=paths["root"],
                owner_visible=None,
                private_decisions=None,
            )

    def test_render_requires_the_exact_supersession_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            self.assert_inventory_error(
                "EVIDENCE_LAYOUT",
                inventory.render_files,
                public_heads=paths["public_heads"],
                owner_visible=paths["owner_visible"],
                public_decisions=paths["public_decisions"],
                private_decisions=paths["private_decisions"],
                capture_metadata=paths["capture_metadata"],
                command_log=paths["command_log"],
                output_root=paths["root"],
                supersession_audit=None,
                _test_profile=True,
            )

    def test_supersession_declared_public_sources_are_exactly_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            values: dict[str, bytes] = {}
            for source_id, (
                relative,
                _status,
            ) in inventory.SUPERSESSION_SOURCE_CONTRACT.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if source_id == "OWNER_LOCAL_PRIVATE_LEDGER":
                    continue
                payload = f"bound source {source_id}\n".encode("utf-8")
                path.write_bytes(payload)
                values[relative] = payload
            subprocess.run(
                ("git", "init", "--quiet", str(root)),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            declared_heads = (
                root
                / inventory.SUPERSESSION_SOURCE_CONTRACT["PUBLIC_REPOSITORY_HEADS"][0]
            )
            public_heads = declared_heads
            private_ledger = (
                root
                / inventory.SUPERSESSION_SOURCE_CONTRACT["OWNER_LOCAL_PRIVATE_LEDGER"][
                    0
                ]
            )
            payloads, records = inventory._supersession_source_payloads(
                evidence_root=root / "evidence/source-review",
                supersession=valid_supersession(),
                public_heads=public_heads,
                private_ledger=private_ledger,
                _test_profile=False,
            )
            expected_labels = [
                relative
                for source_id, (relative, _status) in (
                    inventory.SUPERSESSION_SOURCE_CONTRACT.items()
                )
                if source_id != "OWNER_LOCAL_PRIVATE_LEDGER"
            ]
            self.assertEqual([record["label"] for record in records], expected_labels)
            self.assertEqual(
                {
                    path.relative_to(root).as_posix(): payload
                    for path, payload in payloads.items()
                },
                values,
            )

            relative_public_heads = Path(
                os.path.relpath(declared_heads, Path.cwd())
            )
            relative_payloads, _relative_records = (
                inventory._supersession_source_payloads(
                    evidence_root=root / "evidence/source-review",
                    supersession=valid_supersession(),
                    public_heads=relative_public_heads,
                    private_ledger=private_ledger,
                    _test_profile=False,
                )
            )
            self.assertIn(relative_public_heads, relative_payloads)
            self.assertEqual(
                relative_payloads[relative_public_heads],
                values[
                    inventory.SUPERSESSION_SOURCE_CONTRACT[
                        "PUBLIC_REPOSITORY_HEADS"
                    ][0]
                ],
            )

            roadmap = (
                root / inventory.SUPERSESSION_SOURCE_CONTRACT["CURRENT_NCP_BOUNDARY"][0]
            )
            roadmap.unlink()
            self.assert_inventory_error(
                "SUPERSESSION_STAGED_SOURCE",
                inventory._supersession_source_payloads,
                evidence_root=root / "evidence/source-review",
                supersession=valid_supersession(),
                public_heads=public_heads,
                private_ledger=private_ledger,
                _test_profile=False,
            )
            target = root / "docs/alternate-roadmap.md"
            target.write_text("alternate\n", encoding="utf-8")
            roadmap.symlink_to(target.name)
            self.assert_inventory_error(
                "SUPERSESSION_STAGED_SOURCE",
                inventory._supersession_source_payloads,
                evidence_root=root / "evidence/source-review",
                supersession=valid_supersession(),
                public_heads=public_heads,
                private_ledger=private_ledger,
                _test_profile=False,
            )

        self.assert_inventory_error(
            "GIT_INDEX_ENTRY",
            inventory._parse_git_index,
            b"160000 " + b"a" * 40 + b" 0\tdocs/submodule\0",
        )

    def test_private_commitment_and_owner_local_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            audit_path = paths["root"] / "audit-metadata.json"
            audit, _payload = inventory._load_json(audit_path)
            audit["private_evidence"]["components"][1]["sha256"] = "b" * 64
            inventory._atomic_write(
                audit_path, inventory.canonical_json(audit), private=False
            )
            self.assert_inventory_error(
                "AUDIT_PRIVATE_COMMITMENT",
                inventory.check_files,
                root=paths["root"],
                owner_visible=None,
                private_decisions=None,
                _test_profile=True,
            )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            decisions, _payload = inventory._load_json(paths["private_decisions"])
            decisions["records"][0]["justification"] = "A different explicit decision."
            inventory._atomic_write(
                paths["private_decisions"],
                inventory.canonical_json(decisions),
                private=True,
            )
            self.assert_inventory_error(
                "PRIVATE_GENERATED_DRIFT",
                inventory.check_files,
                root=paths["root"],
                owner_visible=paths["owner_visible"],
                private_decisions=paths["private_decisions"],
                _test_profile=True,
            )

    def test_capture_rejects_output_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "same.jsonl"
            client = FakeRestClient()
            self.assert_inventory_error(
                "EVIDENCE_LAYOUT",
                inventory.capture_files,
                client=client,
                owner_name="sepahead",
                public_heads=target,
                owner_visible=root / "." / "same.jsonl",
                capture_metadata=root / "capture.json",
                command_log=root / "commands.jsonl",
                private_telemetry=root / inventory.PRIVATE_TELEMETRY_BASENAME,
                minimum_remaining=100,
                maximum_pages=2,
                expected_public_repositories=1,
                expected_private_repositories=0,
            )

    def test_private_telemetry_rate_floors_and_public_redaction_are_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            capture, _payload = inventory._load_json(paths["capture_metadata"])
            telemetry, _payload = inventory._load_json(
                paths["private_telemetry"], private=True
            )
            public_records, _payload = inventory._load_jsonl(paths["public_heads"])
            owner_records, _payload = inventory._load_jsonl(
                paths["owner_visible"], private=True
            )

            inventory._validate_private_telemetry(
                telemetry,
                capture,
                public_records=public_records,
                owner_records=owner_records,
            )
            reserve = capture["capture"]["minimum_rate_reserve"]
            identity_floors = (
                reserve + 3 * inventory.MAX_GET_ATTEMPTS,
                reserve + 2 * inventory.MAX_GET_ATTEMPTS,
                reserve + inventory.MAX_GET_ATTEMPTS,
                reserve,
            )
            for index, floor in enumerate(identity_floors):
                mutant = copy.deepcopy(telemetry)
                mutant["identity_rates"][index]["remaining"] = floor - 1
                with self.subTest(identity_index=index):
                    self.assert_inventory_error(
                        "RATE_RESERVE",
                        inventory._validate_private_telemetry,
                        mutant,
                        capture,
                        public_records=public_records,
                        owner_records=owner_records,
                    )

            snapshot_floor = reserve + 2 * inventory.MAX_GET_ATTEMPTS
            mutant = copy.deepcopy(telemetry)
            mutant["summaries"]["PUBLIC"][0]["rate_limit"][
                "minimum_remaining_observed"
            ] = snapshot_floor - 1
            self.assert_inventory_error(
                "PRIVATE_TELEMETRY_SUMMARY",
                inventory._validate_private_telemetry,
                mutant,
                capture,
                public_records=public_records,
                owner_records=owner_records,
            )
            for requests in (1, 7):
                mutant = copy.deepcopy(telemetry)
                mutant["summaries"]["PUBLIC"][0]["requests"] = requests
                with self.subTest(requests=requests):
                    self.assert_inventory_error(
                        "PRIVATE_TELEMETRY_SUMMARY",
                        inventory._validate_private_telemetry,
                        mutant,
                        capture,
                        public_records=public_records,
                        owner_records=owner_records,
                    )

            page_capture = copy.deepcopy(capture)
            page_capture["capture"]["maximum_pages"] = 1
            page_capture["capture"]["invocation_sha256"] = inventory.sha256(
                inventory.canonical_json(
                    inventory._capture_invocation_document(page_capture["capture"])
                )
            )
            page_telemetry = copy.deepcopy(telemetry)
            page_telemetry["summaries"]["PUBLIC"][0]["pages"] = 2
            page_telemetry["summaries"]["PUBLIC"][0]["rows"] = 100
            page_capture["public"]["rows"] = 100
            self.assert_inventory_error(
                "PRIVATE_TELEMETRY_SUMMARY",
                inventory._validate_private_telemetry,
                page_telemetry,
                page_capture,
                public_records=[public_records[0]] * 100,
                owner_records=owner_records,
            )

            def recursive_keys(value: object) -> set[str]:
                if isinstance(value, dict):
                    return set(value) | set().union(
                        *(recursive_keys(item) for item in value.values())
                    )
                if isinstance(value, list):
                    return set().union(*(recursive_keys(item) for item in value))
                return set()

            commands, _payload = inventory._load_jsonl(paths["command_log"])
            forbidden = {
                "pages",
                "rate_limit",
                "remaining",
                "requests",
                "reset_at_utc",
            }
            self.assertFalse(forbidden & recursive_keys(capture))
            self.assertFalse(forbidden & recursive_keys(commands))
            self.assertTrue(forbidden <= recursive_keys(telemetry))

    def test_private_operational_scanner_accepts_large_safe_json_and_is_bounded(
        self,
    ) -> None:
        real_blob = (
            MODULE_PATH.parent.parent
            / "release/0.9.0/current-head/tasks/ch-t002/e0002/evidence/file-review-evidence.json"
        ).read_bytes()
        forbidden_value = {
            "pages": 999,
            "requests": 999,
            "rows": 999,
            "sha256": "f" * 64,
        }
        forbidden_payload = inventory.canonical_json(forbidden_value)
        self.assertFalse(
            inventory._contains_private_operational_payload(
                real_blob,
                frozenset({forbidden_payload}),
                (forbidden_value,),
            )
        )
        adversarial = b'""' * (inventory.MAX_TRACKED_FILES + 1)
        self.assertFalse(
            inventory._contains_private_operational_payload(
                adversarial,
                frozenset({forbidden_payload}),
                (forbidden_value,),
            )
        )
        surrogate_json = json.dumps("\ud800{", ensure_ascii=True).encode("ascii")
        self.assertFalse(
            inventory._contains_private_operational_payload(
                surrogate_json,
                frozenset({forbidden_payload}),
                (forbidden_value,),
            )
        )

    def test_test_profile_artifacts_are_rejected_by_default_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.capture_fixture(Path(temporary))
            capture, _payload = inventory._load_json(paths["capture_metadata"])
            _public, public_payload = inventory._load_jsonl(paths["public_heads"])
            owner, owner_payload = inventory._load_jsonl(
                paths["owner_visible"], private=True
            )
            _commands, command_payload = inventory._load_jsonl(paths["command_log"])
            telemetry_payload = paths["private_telemetry"].read_bytes()
            self.assert_inventory_error(
                "CAPTURE_METADATA_SCHEMA",
                inventory._validate_capture_metadata,
                capture,
                public_payload=public_payload,
                owner_payload=owner_payload,
                command_payload=command_payload,
                owner_records=owner,
                private_telemetry_payload=telemetry_payload,
            )
            self.assert_inventory_error(
                "CAPTURE_METADATA_SCHEMA",
                inventory.render_files,
                public_heads=paths["public_heads"],
                owner_visible=paths["owner_visible"],
                public_decisions=paths["public_decisions"],
                private_decisions=paths["private_decisions"],
                capture_metadata=paths["capture_metadata"],
                command_log=paths["command_log"],
                output_root=paths["root"],
                supersession_audit=paths["supersession_audit"],
            )
            mutant = copy.deepcopy(capture)
            mutant["capture"]["closure_profile"]["profile_version"] = "9.9.9"
            self.assert_inventory_error(
                "CAPTURE_CLOSURE_PROFILE",
                inventory._validate_capture_metadata,
                mutant,
                public_payload=public_payload,
                owner_payload=owner_payload,
                command_payload=command_payload,
                owner_records=owner,
                private_telemetry_payload=telemetry_payload,
                _test_profile=True,
            )
        parser_help = inventory._parser().format_help()
        self.assertNotIn("expected-public", parser_help)
        self.assertNotIn("expected-private", parser_help)
        self.assertEqual(inventory.API_VERSION, "2026-03-10")
        self.assertEqual(
            inventory.PRODUCTION_CLOSURE_PROFILE["source_scope"],
            "Credential-visible GitHub owner repositories via REST API 2026-03-10",
        )

    def test_reviewed_decisions_reject_prose_contradictions_paths_and_stale_bounds(
        self,
    ) -> None:
        capture = self._normalized_head("sepahead/public", 1)
        captures = [capture]
        decision = resolved_decisions(captures)
        invalid_phrases = (
            "Awaiting review before this classification is accepted.",
            "Draft classification recorded for later review.",
            "This classification was not reviewed by a person.",
            "Placeholder classification pending more information.",
            "Review deferred until a later milestone.",
            "This classification needs review before acceptance.",
            "Pending review before the classification is used.",
            "Provisional classification subject to more evidence.",
            "This classification is incomplete and not authoritative.",
            "This classification was assumed without a review.",
            "This classification was guessed from repository metadata.",
            "T.B.D. after the repository can be inspected.",
            "To-do after another person evaluates the repository.",
            "Review is still required before final classification.",
            "Requires review before this classification is final.",
            "Further review is required before this can be final.",
            "This result remains subject to review by another person.",
            "This repository is yet to be reviewed for classification.",
            "Review was not completed for this classification.",
            "This classification is not final for the inventory.",
            "Preliminary classification subject to confirmation.",
            "Temporary classification pending later evidence.",
            "This classification remains open for revision.",
        )
        for phrase in invalid_phrases:
            mutant = copy.deepcopy(decision)
            mutant["records"][0]["justification"] = phrase
            with self.subTest(phrase=phrase):
                self.assert_inventory_error(
                    "DECISION_JUSTIFICATION",
                    inventory.validate_decisions,
                    mutant,
                    captures,
                )
        path_variants = (
            "/秘密",
            "/a b",
            "/a b/c d",
            "C:\\秘密",
            "C:\\A B",
            "(C:\\A B)",
            "path=C:\\A B",
            '"C:\\A B"',
            "\\\\server\\share",
            "\\\\?\\C:\\secret",
            "file:///private/source",
            "localhost/private/source",
            "~/private/source",
            "$HOME/private/source",
            "private%2fsource",
            "private%5csource",
            "docs/private-source.md",
        )
        for path in path_variants:
            mutant = copy.deepcopy(decision)
            mutant["records"][0]["justification"] = (
                f"Explicit review cited {path} as the source record."
            )
            with self.subTest(path=path):
                self.assert_inventory_error(
                    "DECISION_JUSTIFICATION",
                    inventory.validate_decisions,
                    mutant,
                    captures,
                )
        for allowed in (
            "Repository stores draft documentation; it is outside runtime TCB.",
            "Assumed inputs are treated as untrusted during runtime evaluation.",
        ):
            accepted = copy.deepcopy(decision)
            accepted["records"][0]["justification"] = allowed
            inventory.validate_decisions(accepted, captures)

        for field, value in (
            ("review_status", "PENDING"),
            ("classification_status", "PROVISIONAL"),
            ("review_attestation", "I reviewed this repository."),
        ):
            mutant = copy.deepcopy(decision)
            mutant["records"][0][field] = value
            with self.subTest(field=field):
                self.assert_inventory_error(
                    "DECISION_REVIEW_STATUS",
                    inventory.validate_decisions,
                    mutant,
                    captures,
                )
        stale = copy.deepcopy(decision)
        stale["repository_heads_sha256"] = "f" * 64
        self.assert_inventory_error(
            "DECISIONS_HEADS_DIGEST",
            inventory.validate_decisions,
            stale,
            captures,
        )
        for date in ("2026-08-01", "2026-08-03"):
            mutant = copy.deepcopy(decision)
            mutant["records"][0]["review_date"] = date
            with self.subTest(date=date):
                self.assert_inventory_error(
                    "DECISION_REVIEW_DATE",
                    inventory.validate_decisions,
                    mutant,
                    captures,
                    review_not_before=inventory.dt.date(2026, 8, 2),
                    review_not_after=inventory.dt.date(2026, 8, 2),
                )

    def test_account_identity_and_empty_repository_csv_use_exact_terms(self) -> None:
        owner = inventory._identity_record(identity_payload(), "IDENTITY")
        self.assertEqual(set(owner), {"account_id", "login", "node_id"})
        self.assertNotIn(
            "expected_owner_repository_id", inventory.PRODUCTION_CLOSURE_PROFILE
        )
        self.assertEqual(
            inventory.PRODUCTION_CLOSURE_PROFILE["expected_owner_account_id"],
            OWNER["account_id"],
        )
        empty = self._normalized_head("sepahead/empty", 42)
        empty["default_branch"] = None
        empty["exact_head"] = None
        empty["head_state"] = "EMPTY_REPOSITORY"
        decision = resolved_decisions([empty])
        decisions = inventory.validate_decisions(decision, [empty])
        output = inventory.classification_csv(
            inventory.joined_records([empty], decisions)
        ).decode("utf-8")
        row = next(csv.DictReader(io.StringIO(output)))
        self.assertEqual(row["repository_id"], "42")
        self.assertEqual(row["head_state"], "EMPTY_REPOSITORY")
        self.assertEqual(row["default_branch"], "")
        self.assertEqual(row["exact_head"], "")

    def test_assurance_diagram_is_accessible_deterministic_and_cli_checked(
        self,
    ) -> None:
        project_root = MODULE_PATH.parent.parent
        diagram_path = (
            project_root / "docs/assets" / inventory.ECOSYSTEM_DIAGRAM_BASENAME
        )
        expected = inventory.ecosystem_source_inventory_svg()
        self.assertEqual(diagram_path.read_bytes(), expected)

        document = ET.fromstring(expected)
        namespace = {"svg": "http://www.w3.org/2000/svg"}
        self.assertEqual(document.attrib["role"], "img")
        self.assertEqual(
            document.attrib["aria-labelledby"], "diagram-title diagram-desc"
        )
        title = document.find("svg:title", namespace)
        description = document.find("svg:desc", namespace)
        self.assertIsNotNone(title)
        self.assertIsNotNone(description)
        self.assertEqual(title.attrib["id"], "diagram-title")
        self.assertEqual(description.attrib["id"], "diagram-desc")
        self.assertGreater(len((title.text or "").strip()), 20)
        self.assertGreater(len((description.text or "").strip()), 400)
        self.assertIn("Public checking remains commitment-only", description.text or "")
        all_ids = [item.attrib["id"] for item in document.iter() if "id" in item.attrib]
        self.assertEqual(len(all_ids), len(set(all_ids)))
        referenced_ids = document.attrib["aria-labelledby"].split()
        self.assertEqual(len(referenced_ids), len(set(referenced_ids)))
        self.assertTrue(set(referenced_ids) <= set(all_ids))
        rendered = expected.decode("utf-8")
        for required_text in (
            "174 public + 43 private = 217 owner-visible",
            "CAPTURE COMPLETE only with exact tool binding",
            "AUTOMATED FACTUAL REVIEW",
            "OWNER APPROVAL NOT ESTABLISHED",
            "Receipt-derived seal state",
            "Captured observations + maintained source set",
            "four public supersession blobs",
            "owner-local ledger commitment",
            "queued work rejected; groups reaped",
            "OWNER-LOCAL • MODE 0600",
            "Whole stage-zero regular-blob scan",
            "manifest: mode | path | bytes | git_oid",
            "| independently computed blob_sha256",
            "COMMITMENT_ONLY_NOT_VERIFIED",
            "AUDIT_STAGED_FINAL required",
            "all authority fields false",
            "NO_GO",
            "@media (prefers-reduced-motion:reduce)",
            ".flow{animation:none;stroke-dasharray:none}",
            ".motion{display:none}",
        ):
            with self.subTest(required_text=required_text):
                self.assertIn(required_text, rendered)
        self.assertNotIn("HUMAN REVIEW", rendered)
        self.assertNotIn("EXPLICIT OWNER REVIEW", rendered)
        self.assertEqual(
            len(inventory.SUPERSESSION_SOURCE_CONTRACT),
            5,
        )
        self.assertGreaterEqual(
            len(document.findall(".//svg:animateMotion", namespace)),
            2,
        )
        motion_circles = [
            item
            for item in document.findall(".//svg:circle", namespace)
            if "motion" in item.attrib.get("class", "").split()
        ]
        self.assertEqual(len(motion_circles), 2)
        self.assertTrue(
            all("cx" in item.attrib and "cy" in item.attrib for item in motion_circles)
        )
        self.assertNotIn("href=", rendered)
        self.assertNotIn("prevents post-signal spawn", rendered)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / inventory.ECOSYSTEM_DIAGRAM_BASENAME
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    inventory.main(["diagram", "--output", str(output)]),
                    0,
                )
                self.assertEqual(
                    inventory.main(["diagram", "--output", str(output), "--check"]),
                    0,
                )
            self.assertEqual(output.read_bytes(), expected)
            output.write_bytes(expected + b" ")
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    inventory.main(["diagram", "--output", str(output), "--check"]),
                    1,
                )
            self.assertIn("ERROR DIAGRAM_DRIFT", stderr.getvalue())

    @staticmethod
    def _normalized_head(repository: str, repository_id: int) -> dict[str, object]:
        return {
            "archived": False,
            "canonical_url": f"https://github.com/{repository}",
            "default_branch": "main",
            "exact_head": oid(repository_id),
            "fork": False,
            "head_state": "COMMIT",
            "language": "Rust",
            "license": "MIT",
            "owner": "sepahead",
            "owner_id": OWNER["account_id"],
            "parent": None,
            "pushed_at": "2026-08-01T10:11:12Z",
            "repository": repository,
            "repository_id": repository_id,
            "schema_version": inventory.SCHEMA_VERSION,
            "updated_at": "2026-08-01T10:11:13Z",
            "visibility": "PUBLIC",
        }


if __name__ == "__main__":
    unittest.main(verbosity=2)
