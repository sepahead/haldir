#!/usr/bin/env python3
"""Independently verify the development-only live Gate smoke artifact."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_zenoh import (  # noqa: E402
    DEFAULT_PROFILE,
    load_profile,
    render_bundle,
    verify_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "evidence" / "12-live-gate-dev-smoke"
PINS_PATH = ROOT / "tools" / "pins.toml"
DOCKERFILE_PATH = ROOT / "tools" / "live-gate-dev-smoke" / "Dockerfile"
DOCKERIGNORE_PATH = ROOT / "tools" / "live-gate-dev-smoke" / "Dockerfile.dockerignore"

BUILDER_IMAGE = (
    "docker.io/library/rust@"
    "sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc"
)
ROUTER_IMAGE = (
    "docker.io/eclipse/zenoh@"
    "sha256:157965d71e0bfd0a044d76a985ff0e5c306ad3968929168fb9678cd2a7fec23f"
)
NCP_COMMIT = "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
NCP_SOURCE = f"git+https://github.com/sepahead/NCP?rev={NCP_COMMIT}#{NCP_COMMIT}"

PROVISION_BINARY = "/usr/local/bin/live_gate_dev_fixture_provision"
BIND_BINARY = "/usr/local/bin/live_gate_dev_bind_shutdown"
GATE_CONFIG_PATH = "/etc/haldir-live-gate/gate.json"
RUNTIME_CONFIG_ROOT = "/etc/haldir-secure-reference-v1"
RUNTIME_SECRET_ROOT = "/run/secrets/haldir-secure-reference-v1"
GATE_SECRET_FILES = ["ca.pem", "gate.cert.pem", "gate.key.pem"]
ROUTER_SECRET_FILES = ["ca.pem", "router.cert.pem", "router.key.pem"]
EXAMPLE_NAMES = [
    "live_gate_dev_fixture_provision",
    "live_gate_dev_bind_shutdown",
]

PROVISION_SCRIPT = f"""
set +e
{PROVISION_BINARY} /fixture/gate /fixture/provision-result.json
status=$?
printf '%s\\n' "$status" > /run/haldir-provision-exit
while :; do sleep 3600; done
""".strip()

BIND_SCRIPT = f"""
set +e
{BIND_BINARY} /fixture {GATE_CONFIG_PATH} /evidence/bind-result.json
status=$?
printf '%s\\n' "$status" > /run/haldir-bind-exit
while :; do sleep 3600; done
""".strip()

HEX_64 = re.compile(r"[0-9a-f]{64}")
HEX_40 = re.compile(r"[0-9a-f]{40}")
SUFFIX = re.compile(r"[0-9a-f]{12}")
PRIVATE_KEY_MARKER = re.compile(
    rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----|"
    rb"-----BEGIN OPENSSH PRIVATE KEY-----"
)
HOST_PATH_MARKER = re.compile(rb"(?:/Users/|/home/|/var/folders/|[A-Za-z]:\\\\)")

JOURNAL_KEYS = {
    "active_sequence",
    "closed_active_tail",
    "completed_segments",
    "discarded_pending_creation",
    "discovered_segments",
    "quiesced",
    "recovered_records",
    "recovery_unknown_events",
    "total_bytes",
    "truncated_tail_bytes",
}
INGRESS_COUNTER_KEYS = {
    "accepted",
    "non_put_dropped",
    "oversize_dropped",
    "queue_full_dropped",
    "receiver_closed_dropped",
    "unexpected_key_dropped",
}
NEGATIVE_EVIDENCE = {
    "acl_exclusivity_evidence": False,
    "authenticated_control_ingress": False,
    "commands_published_by_target": 0,
    "complete_mediation_evidence": False,
    "credential_custody_evidence": False,
    "intents_processed_by_target": 0,
    "journal_finalization_evidence": False,
    "production_ready": False,
    "remote_session_retirement_evidence": False,
    "zid_is_authenticated_principal": False,
}
PROVISION_STAGES = [
    "static-config-validated",
    "outer-lock-acquired",
    "state-provisioned",
    "journal-provisioned",
]
BIND_STAGES = [
    "static-config-validated",
    "outer-lock-acquired",
    "zenoh-config-validated",
    "state-opened",
    "journal-opened",
    "local-activation-accepted",
    "session-opened",
    "aggregate-bound",
    "aggregate-shutdown",
]
LIMITATIONS = [
    "the generator performs no independent verification or evidence promotion",
    "the bind target processes zero intents and publishes zero commands",
    "local bind and shutdown returns do not prove delivery or remote cleanup",
    "the fixture uses local-rewritable development state and deterministic public test keys",
    "ephemeral test PKI and disposable containers do not prove production credential custody",
    "the cooperative lock and path checks assume a trusted host",
    "abrupt process, host, or daemon loss can require manual cleanup; build cache is not campaign evidence",
]


class VerificationError(RuntimeError):
    """The artifact is absent, malformed, incomplete, or inconsistent."""


def canonical_json(value: Any) -> bytes:
    """Return the generator's stable JSON representation."""
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{name} must be a JSON object")
    return value


def require_array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{name} must be a JSON array")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        raise VerificationError(
            f"{name} keys differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def require_int(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise VerificationError(f"{name} must be an integer >= {minimum}")
    return value


def load_json(path: Path, *, canonical: bool = False) -> Any:
    """Load duplicate-free strict JSON and optionally require canonical bytes."""

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(
            f"cannot read strict JSON {path.name}: {error}"
        ) from error
    if canonical and raw != canonical_json(value):
        raise VerificationError(f"{path.name} is not canonical generator JSON")
    return value


def verify_no_secrets_or_host_paths(evidence: Path) -> None:
    """Reject filesystem indirection, private-key bytes, and host path leakage."""
    if evidence.is_symlink():
        raise VerificationError("evidence root is a symbolic link")
    root_bytes = str(ROOT).encode()
    for path in evidence.rglob("*"):
        if path.is_symlink():
            raise VerificationError("evidence contains a symbolic link")
        if path.is_dir():
            continue
        if not path.is_file():
            raise VerificationError("evidence contains a non-file filesystem entry")
        name = path.name.lower()
        if name.endswith((".key", ".key.pem", ".p12", ".pfx")) or ".key." in name:
            raise VerificationError("evidence contains a private-key file")
        data = path.read_bytes()
        if PRIVATE_KEY_MARKER.search(data):
            raise VerificationError("evidence contains private-key material")
        if root_bytes in data or HOST_PATH_MARKER.search(data):
            raise VerificationError(
                "evidence contains an unsanitized developer-host path"
            )


def verify_checksums(evidence: Path) -> None:
    """Verify canonical, duplicate-free SHA-256 coverage of every retained file."""
    checksum_path = evidence / "checksums.sha256"
    try:
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise VerificationError("cannot read checksums.sha256") from error
    if not lines:
        raise VerificationError("checksums.sha256 is empty")
    recorded: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if match is None:
            raise VerificationError("checksums.sha256 has a noncanonical line")
        digest, relative = match.groups()
        pure = PurePosixPath(relative)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or relative == "checksums.sha256"
            or relative in recorded
        ):
            raise VerificationError("checksums.sha256 has an unsafe or duplicate path")
        recorded[relative] = digest
        order.append(relative)
    if order != sorted(order):
        raise VerificationError("checksums.sha256 paths are not canonically sorted")
    actual = {
        path.relative_to(evidence).as_posix()
        for path in evidence.rglob("*")
        if path.is_file() and path != checksum_path
    }
    if set(recorded) != actual:
        raise VerificationError("checksum coverage differs from the complete file set")
    for relative, expected in recorded.items():
        actual_digest = sha256_bytes((evidence / relative).read_bytes())
        if actual_digest != expected:
            raise VerificationError(f"checksum mismatch: {relative}")


def verify_configs(evidence: Path, profile: dict[str, Any]) -> dict[str, bytes]:
    """Require the exact deterministic render of the current reviewed profile."""
    expected = render_bundle(profile)
    config_root = evidence / "configs"
    actual = {
        path.relative_to(config_root).as_posix(): path.read_bytes()
        for path in sorted(config_root.rglob("*"))
        if path.is_file()
    }
    verify_bundle(profile, actual)
    if actual != expected:
        raise VerificationError("configs differ from the exact current profile render")
    return actual


def verify_journal(value: Any, name: str, expected: dict[str, Any]) -> dict[str, Any]:
    journal = require_object(value, name)
    require_exact_keys(journal, JOURNAL_KEYS, name)
    for key in (
        "completed_segments",
        "discovered_segments",
        "recovered_records",
        "recovery_unknown_events",
        "total_bytes",
        "truncated_tail_bytes",
    ):
        require_int(journal.get(key), f"{name}.{key}")
    active = journal.get("active_sequence")
    if active is not None:
        require_int(active, f"{name}.active_sequence", minimum=1)
    for key in ("closed_active_tail", "discarded_pending_creation", "quiesced"):
        if not isinstance(journal.get(key), bool):
            raise VerificationError(f"{name}.{key} must be a boolean")
    if journal.get("total_bytes") == 0:
        raise VerificationError(f"{name}.total_bytes must be positive")
    for key, wanted in expected.items():
        if journal.get(key) != wanted:
            raise VerificationError(f"{name}.{key} differs from the exact transition")
    return journal


def verify_provision_result(evidence: Path) -> dict[str, Any]:
    result = require_object(
        load_json(evidence / "results" / "provision-result.json", canonical=True),
        "provision result",
    )
    require_exact_keys(
        result,
        {
            "anchor_protection",
            "development_only",
            "journal",
            "mode",
            "ncp_wire_profile",
            "production_claim",
            "provisioned",
            "runtime_profile",
            "schema_version",
            "stages",
            "startup_generation",
            "status",
        },
        "provision result",
    )
    exact = {
        "anchor_protection": "local-rewritable",
        "development_only": True,
        "mode": "development-live-fixture-provision-v1",
        "ncp_wire_profile": "exact-ncp-v0.8-json",
        "production_claim": False,
        "provisioned": True,
        "runtime_profile": "declared-live-zenoh",
        "schema_version": 1,
        "stages": PROVISION_STAGES,
        "status": "pass",
    }
    for key, wanted in exact.items():
        if result.get(key) != wanted:
            raise VerificationError(f"provision result has invalid {key}")
    require_int(
        result.get("startup_generation"), "provision startup_generation", minimum=1
    )
    verify_journal(
        result.get("journal"),
        "provision journal",
        {
            "active_sequence": 1,
            "closed_active_tail": False,
            "completed_segments": 0,
            "discarded_pending_creation": False,
            "discovered_segments": 0,
            "quiesced": False,
            "recovered_records": 0,
            "recovery_unknown_events": 0,
            "truncated_tail_bytes": 0,
        },
    )
    return result


def require_byte_array(value: Any, name: str) -> list[int]:
    values = require_array(value, name)
    if len(values) != 16 or any(
        isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 255
        for item in values
    ):
        raise VerificationError(f"{name} must be exactly sixteen bytes")
    if not any(values):
        raise VerificationError(f"{name} must not be all zero")
    return values


def verify_bind_result(
    evidence: Path, profile: dict[str, Any], provision: dict[str, Any]
) -> dict[str, Any]:
    result = require_object(
        load_json(evidence / "results" / "bind-result.json", canonical=True),
        "bind result",
    )
    require_exact_keys(
        result,
        {
            "anchor_protection",
            "bind_returned_ok",
            "controller_id",
            "development_only",
            "discarded_events",
            "gate_boot_id",
            "gate_output_epoch",
            "ingress_counters",
            "intent_route",
            "journal",
            "lease_term",
            "local_returns",
            "mode",
            "ncp_wire_profile",
            "negative_evidence",
            "production_claim",
            "provisioned",
            "runtime_profile",
            "schema_version",
            "shutdown_returned_ok",
            "stages",
            "startup_generation",
            "startup_recovery",
            "status",
            "zid",
        },
        "bind result",
    )
    exact = {
        "anchor_protection": "local-rewritable",
        "bind_returned_ok": True,
        "controller_id": "controller-a",
        "development_only": True,
        "intent_route": profile["routes"]["controller_a_intent"],
        "local_returns": {
            "aggregate_bind": True,
            "aggregate_shutdown": True,
            "session_open": True,
        },
        "mode": "development-live-bind-smoke-v1",
        "ncp_wire_profile": "exact-ncp-v0.8-json",
        "negative_evidence": NEGATIVE_EVIDENCE,
        "production_claim": False,
        "provisioned": False,
        "runtime_profile": "declared-live-zenoh",
        "schema_version": 1,
        "shutdown_returned_ok": True,
        "stages": BIND_STAGES,
        "startup_recovery": "clean",
        "status": "pass",
    }
    for key, wanted in exact.items():
        if result.get(key) != wanted:
            raise VerificationError(f"bind result has invalid {key}")

    generation = require_int(
        result.get("startup_generation"), "bind startup_generation", minimum=1
    )
    provision_generation = require_int(
        provision.get("startup_generation"), "provision startup_generation", minimum=1
    )
    if generation != provision_generation + 1:
        raise VerificationError("bind did not perform exactly the next durable boot")
    if result.get("lease_term") != generation:
        raise VerificationError("bind lease term is not the fresh boot generation")
    require_byte_array(result.get("gate_boot_id"), "gate_boot_id")
    require_byte_array(result.get("gate_output_epoch"), "gate_output_epoch")

    discarded = require_int(result.get("discarded_events"), "discarded_events")
    counters = require_object(result.get("ingress_counters"), "ingress counters")
    require_exact_keys(counters, INGRESS_COUNTER_KEYS, "ingress counters")
    for key in INGRESS_COUNTER_KEYS:
        require_int(counters.get(key), f"ingress counters.{key}")
    if counters["accepted"] != discarded:
        raise VerificationError(
            "accepted ingress was not exactly drained and discarded"
        )

    verify_journal(
        result.get("journal"),
        "bind journal",
        {
            "active_sequence": 2,
            "closed_active_tail": True,
            "completed_segments": 1,
            "discarded_pending_creation": False,
            "discovered_segments": 1,
            "quiesced": False,
            "recovered_records": 0,
            "recovery_unknown_events": 0,
            "truncated_tail_bytes": 0,
        },
    )

    zid = require_object(result.get("zid"), "zid")
    require_exact_keys(
        zid, {"authenticated_principal", "operational_identifier"}, "zid"
    )
    if (
        zid.get("authenticated_principal") is not False
        or not isinstance(zid.get("operational_identifier"), str)
        or not zid["operational_identifier"]
    ):
        raise VerificationError("zid is not a non-authenticated operational identifier")
    return result


def load_and_verify_pins() -> dict[str, Any]:
    """Load the reviewed pin source and reject drift in every smoke-relevant pin."""
    try:
        pins = tomllib.loads(PINS_PATH.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"cannot load tools/pins.toml: {error}") from error
    toolchain = require_object(pins.get("toolchain"), "pins.toolchain")
    ncp = require_object(pins.get("ncp"), "pins.ncp")
    zenoh = require_object(pins.get("zenoh"), "pins.zenoh")
    live = require_object(pins.get("live_transport"), "pins.live_transport")
    if (
        toolchain.get("rust_channel") != "1.96.0"
        or ncp.get("tag") != "v0.8.0"
        or ncp.get("commit") != NCP_COMMIT
        or ncp.get("wire_version") != "0.8"
        or ncp.get("capability_profile") != "PRE_AUTHORITY_ACL_ONLY"
        or zenoh.get("version") != "1.9.0"
        or zenoh.get("default_features") is not False
        or zenoh.get("features") != ["transport_tls"]
        or live.get("probe_builder_image") != BUILDER_IMAGE
        or live.get("router_image") != ROUTER_IMAGE
    ):
        raise VerificationError(
            "current smoke-relevant pin set differs from the reviewed profile"
        )
    return pins


def git_blob(commit: str, relative: str) -> bytes:
    process = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if process.returncode != 0:
        raise VerificationError(f"source commit does not contain {relative}")
    return process.stdout


def verify_cargo_lock(raw: bytes) -> None:
    """Verify the exact NCP and Zenoh source pins represented by Cargo.lock."""
    try:
        lock = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError("source Cargo.lock is malformed") from error
    if lock.get("version") != 4:
        raise VerificationError("source Cargo.lock is not lockfile schema 4")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise VerificationError("source Cargo.lock package array is malformed")

    def one_package(name: str) -> dict[str, Any]:
        matches = [
            item
            for item in packages
            if isinstance(item, dict) and item.get("name") == name
        ]
        if len(matches) != 1:
            raise VerificationError(
                f"source Cargo.lock must contain exactly one {name}"
            )
        return matches[0]

    ncp = one_package("ncp-core")
    zenoh = one_package("zenoh")
    gate = one_package("haldir-gate")
    if ncp.get("version") != "0.8.0" or ncp.get("source") != NCP_SOURCE:
        raise VerificationError(
            "source Cargo.lock does not select exact NCP v0.8 revision"
        )
    if zenoh.get("version") != "1.9.0":
        raise VerificationError("source Cargo.lock does not select exact Zenoh 1.9.0")
    dependencies = gate.get("dependencies")
    if not isinstance(dependencies, list) or not {
        "haldir-transport-zenoh",
        "serde_json",
        "tokio",
    }.issubset(dependencies):
        raise VerificationError("haldir-gate lock entry omits live-smoke dependencies")


def verify_manifest(
    evidence: Path,
    profile: dict[str, Any],
    provision: dict[str, Any],
    bind: dict[str, Any],
    configs: dict[str, bytes],
) -> dict[str, Any]:
    """Verify schema-v2 bindings to source, pins, inputs, results, and cleanup."""
    manifest = require_object(
        load_json(evidence / "manifest.json", canonical=True), "manifest"
    )
    require_exact_keys(
        manifest,
        {
            "bind_result_sha256",
            "builder_image",
            "cargo_lock_sha256",
            "cleanup",
            "dockerfile_sha256",
            "example_executable_sha256",
            "examples",
            "finished_at_utc",
            "fixture_transition",
            "gate_config_sha256",
            "generator_actions",
            "limitations",
            "profile_id",
            "profile_sha256",
            "provision_result_sha256",
            "router_image",
            "schema_version",
            "source_commit",
            "source_dirty",
            "source_snapshot_sha256",
            "smoke_image_id",
            "started_at_utc",
        },
        "manifest",
    )
    exact = {
        "builder_image": BUILDER_IMAGE,
        "examples": EXAMPLE_NAMES,
        "fixture_transition": "ProvisionNew-offline-then-OpenExisting-live",
        "generator_actions": {
            "independent_verification_performed": False,
            "promotion_performed": False,
        },
        "limitations": LIMITATIONS,
        "profile_id": "haldir-secure-reference-v1",
        "router_image": ROUTER_IMAGE,
        "schema_version": 2,
        "source_dirty": False,
    }
    for key, wanted in exact.items():
        if manifest.get(key) != wanted:
            raise VerificationError(f"manifest has invalid {key}")

    cleanup = require_object(manifest.get("cleanup"), "manifest.cleanup")
    require_exact_keys(
        cleanup,
        {
            "gate_container_removed",
            "inspector_container_removed",
            "network_removed",
            "private_material_removed",
            "provision_container_removed",
            "raw_fixture_removed",
            "router_container_removed",
            "smoke_image_removed",
        },
        "manifest.cleanup",
    )
    if any(value is not True for value in cleanup.values()):
        raise VerificationError("manifest reports incomplete disposable cleanup")

    digest_fields = (
        "bind_result_sha256",
        "cargo_lock_sha256",
        "dockerfile_sha256",
        "gate_config_sha256",
        "profile_sha256",
        "provision_result_sha256",
        "source_snapshot_sha256",
    )
    for field in digest_fields:
        value = manifest.get(field)
        if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
            raise VerificationError(f"manifest {field} is not lowercase SHA-256")
    smoke_image_id = manifest.get("smoke_image_id")
    if (
        not isinstance(smoke_image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", smoke_image_id) is None
    ):
        raise VerificationError("manifest smoke_image_id is malformed")
    executables = require_object(
        manifest.get("example_executable_sha256"), "manifest.example_executable_sha256"
    )
    require_exact_keys(
        executables, set(EXAMPLE_NAMES), "manifest.example_executable_sha256"
    )
    if any(
        not isinstance(value, str) or HEX_64.fullmatch(value) is None
        for value in executables.values()
    ):
        raise VerificationError("manifest executable digest is malformed")
    if len(set(executables.values())) != 2:
        raise VerificationError(
            "the two example executable digests unexpectedly collide"
        )

    if manifest["provision_result_sha256"] != sha256_bytes(canonical_json(provision)):
        raise VerificationError("manifest provision result digest is inconsistent")
    if manifest["bind_result_sha256"] != sha256_bytes(canonical_json(bind)):
        raise VerificationError("manifest bind result digest is inconsistent")
    if manifest["gate_config_sha256"] != sha256_bytes(configs["clients/gate.json"]):
        raise VerificationError("manifest Gate config digest is inconsistent")

    commit = manifest.get("source_commit")
    if not isinstance(commit, str) or HEX_40.fullmatch(commit) is None:
        raise VerificationError(
            "manifest source_commit is not a full lowercase Git commit"
        )
    current_profile = DEFAULT_PROFILE.read_bytes()
    source_profile = git_blob(commit, "deploy/secure-reference-v1/profile.json")
    if source_profile != current_profile:
        raise VerificationError(
            "source commit profile differs from the current reviewed profile"
        )
    if manifest["profile_sha256"] != sha256_bytes(source_profile):
        raise VerificationError("manifest profile digest is inconsistent")

    cargo_lock = git_blob(commit, "Cargo.lock")
    verify_cargo_lock(cargo_lock)
    if manifest["cargo_lock_sha256"] != sha256_bytes(cargo_lock):
        raise VerificationError("manifest Cargo.lock digest is inconsistent")
    dockerfile = git_blob(commit, "tools/live-gate-dev-smoke/Dockerfile")
    if dockerfile != DOCKERFILE_PATH.read_bytes():
        raise VerificationError(
            "source Dockerfile differs from the current reviewed recipe"
        )
    if manifest["dockerfile_sha256"] != sha256_bytes(dockerfile):
        raise VerificationError("manifest Dockerfile digest is inconsistent")
    source_dockerignore = git_blob(
        commit, "tools/live-gate-dev-smoke/Dockerfile.dockerignore"
    )
    if source_dockerignore != DOCKERIGNORE_PATH.read_bytes():
        raise VerificationError(
            "source Docker build-context allowlist differs from current"
        )
    dockerfile_text = dockerfile.decode()
    if (
        dockerfile_text.count(f"FROM {BUILDER_IMAGE}") != 2
        or "--locked" not in dockerfile_text
        or "--release" not in dockerfile_text
        or "--features live-gate-dev-smoke" not in dockerfile_text
        or "--example live_gate_dev_fixture_provision" not in dockerfile_text
        or "--example live_gate_dev_bind_shutdown" not in dockerfile_text
    ):
        raise VerificationError(
            "source Dockerfile does not build both exact locked examples"
        )

    archive = subprocess.run(
        ["git", "archive", "--format=tar", commit],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if archive.returncode != 0:
        raise VerificationError("manifest source commit is unavailable locally")
    if sha256_bytes(archive.stdout) != manifest["source_snapshot_sha256"]:
        raise VerificationError(
            "manifest source snapshot digest differs from git archive"
        )

    try:
        started_text = manifest["started_at_utc"]
        finished_text = manifest["finished_at_utc"]
        if not isinstance(started_text, str) or not isinstance(finished_text, str):
            raise ValueError
        started = dt.datetime.fromisoformat(started_text.replace("Z", "+00:00"))
        finished = dt.datetime.fromisoformat(finished_text.replace("Z", "+00:00"))
    except ValueError as error:
        raise VerificationError("manifest timestamps are not ISO-8601 UTC") from error
    if (
        not started_text.endswith("Z")
        or not finished_text.endswith("Z")
        or finished < started
    ):
        raise VerificationError("manifest timestamp interval is inconsistent")
    return manifest


def verify_pki(evidence: Path, profile: dict[str, Any]) -> None:
    pki = require_object(load_json(evidence / "pki.json", canonical=True), "pki")
    require_exact_keys(
        pki,
        {
            "ca_sha256_fingerprint",
            "ca_subject",
            "identities",
            "mounted_secret_sets",
            "private_keys_retained",
            "schema_version",
        },
        "pki",
    )
    if (
        pki.get("schema_version") != 1
        or pki.get("private_keys_retained") is not False
        or pki.get("ca_subject") != "CN=haldir-live-campaign-ephemeral-ca"
        or pki.get("mounted_secret_sets")
        != {"gate": GATE_SECRET_FILES, "router": ROUTER_SECRET_FILES}
    ):
        raise VerificationError(
            "PKI inventory has an invalid schema or secret mount set"
        )
    ca_fingerprint = pki.get("ca_sha256_fingerprint")
    if not isinstance(ca_fingerprint, str) or HEX_64.fullmatch(ca_fingerprint) is None:
        raise VerificationError("PKI CA fingerprint is malformed")
    identities = require_object(pki.get("identities"), "pki.identities")
    expected_names = {
        "router": profile["router"]["certificate_common_name"],
        **{
            principal: value["certificate_common_name"]
            for principal, value in profile["principals"].items()
        },
    }
    require_exact_keys(identities, set(expected_names), "pki.identities")
    fingerprints: set[str] = set()
    for identity, common_name in expected_names.items():
        record = require_object(identities[identity], f"pki identity {identity}")
        require_exact_keys(
            record,
            {"common_name", "purpose", "sha256_fingerprint", "subject_alt_names"},
            f"pki identity {identity}",
        )
        fingerprint = record.get("sha256_fingerprint")
        purpose = "server" if identity == "router" else "client"
        sans = ["DNS:router.haldir.invalid"] if identity == "router" else []
        if (
            record.get("common_name") != common_name
            or record.get("purpose") != purpose
            or record.get("subject_alt_names") != sans
            or not isinstance(fingerprint, str)
            or HEX_64.fullmatch(fingerprint) is None
        ):
            raise VerificationError(f"PKI identity binding is malformed: {identity}")
        fingerprints.add(fingerprint)
    if len(fingerprints) != len(expected_names) or ca_fingerprint in fingerprints:
        raise VerificationError("PKI fingerprints are not globally distinct")
    log = (evidence / "logs" / "pki-verification.log").read_text(encoding="utf-8")
    normalized = log.lower().replace(":", "")
    for fingerprint in {ca_fingerprint, *fingerprints}:
        if fingerprint not in normalized:
            raise VerificationError("PKI log omits a retained certificate fingerprint")
    for common_name in expected_names.values():
        if common_name not in log:
            raise VerificationError("PKI log omits an exact certificate common name")
    if (
        "DNS:router.haldir.invalid" not in log
        or "TLS Web Server Authentication" not in log
        or "TLS Web Client Authentication" not in log
    ):
        raise VerificationError("PKI log omits SAN or EKU verification")


def option_value(argv: list[str], option: str) -> str:
    positions = [index for index, value in enumerate(argv) if value == option]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise VerificationError(f"command does not contain exactly one {option}")
    return argv[positions[0] + 1]


def verify_provision_export_commands(
    records: list[dict[str, Any]], provision_container: str
) -> list[str]:
    """Require the one supported export path from the provisioner's tmpfs."""
    argvs = [record["argv"] for record in records]
    provision_export = [
        "docker",
        "exec",
        provision_container,
        "tar",
        "-C",
        "/fixture",
        "-cf",
        "-",
        "gate",
        "provision-result.json",
    ]
    if argvs.count(provision_export) != 1:
        raise VerificationError(
            "campaign did not retain exactly one provisioned fixture archive export"
        )
    marker_poll = [
        "docker",
        "exec",
        provision_container,
        "cat",
        "/run/haldir-provision-exit",
    ]
    running_inspect = [
        "docker",
        "inspect",
        "--format",
        "{{.State.Running}}",
        provision_container,
    ]
    marker_indices = [
        index for index, record in enumerate(records) if record["argv"] == marker_poll
    ]
    successful_markers = [
        index for index in marker_indices if records[index]["exit_code"] == 0
    ]
    if len(successful_markers) != 1:
        raise VerificationError(
            "provisioner exit marker was not observed exactly once successfully"
        )
    successful_marker = successful_markers[0]
    if not marker_indices or marker_indices[-1] != successful_marker:
        raise VerificationError("provisioner polled again after its successful marker")
    failed_marker_indices = marker_indices[:-1]
    expected_running_inspects = [index + 1 for index in failed_marker_indices]
    actual_running_inspects = [
        index
        for index, record in enumerate(records)
        if record["argv"] == running_inspect
    ]
    if actual_running_inspects != expected_running_inspects or any(
        records[index]["exit_code"] != 0 for index in actual_running_inspects
    ):
        raise VerificationError(
            "failed provisioner marker polls were not paired with running-state checks"
        )
    export_index = argvs.index(provision_export)
    stop = ["docker", "stop", "--time", "1", provision_container]
    if argvs.count(stop) != 1:
        raise VerificationError("provisioner was not stopped exactly once")
    stop_index = argvs.index(stop)
    if not successful_marker < export_index < stop_index:
        raise VerificationError(
            "provisioner marker, fixture export, and stop order differs"
        )

    allowed_touching_commands = {
        tuple(marker_poll),
        tuple(running_inspect),
        tuple(provision_export),
        ("docker", "logs", provision_container),
        tuple(stop),
        ("docker", "container", "inspect", provision_container),
        ("docker", "rm", "--force", provision_container),
    }
    for argv in argvs:
        touches_provisioner = any(
            item == provision_container or item.startswith(f"{provision_container}:")
            for item in argv
        )
        if not touches_provisioner:
            continue
        is_provision_run = (
            argv[:2] == ["docker", "run"]
            and "--name" in argv
            and option_value(argv, "--name") == provision_container
        )
        if not is_provision_run and tuple(argv) not in allowed_touching_commands:
            raise VerificationError(
                "provisioner contains an unexpected lifecycle or export command"
            )
    return provision_export


def verify_gate_export_commands(
    records: list[dict[str, Any]], gate_container: str
) -> list[str]:
    """Require one ordered, bounded tar export from the live Gate tmpfs."""
    argvs = [record["argv"] for record in records]
    gate_export = [
        "docker",
        "exec",
        gate_container,
        "tar",
        "-C",
        "/evidence",
        "-cf",
        "-",
        "bind-result.json",
    ]
    if argvs.count(gate_export) != 1:
        raise VerificationError(
            "campaign did not retain exactly one Gate result archive export"
        )
    marker_poll = [
        "docker",
        "exec",
        gate_container,
        "cat",
        "/run/haldir-bind-exit",
    ]
    running_inspect = [
        "docker",
        "inspect",
        "--format",
        "{{.State.Running}}",
        gate_container,
    ]
    marker_indices = [
        index for index, record in enumerate(records) if record["argv"] == marker_poll
    ]
    successful_markers = [
        index for index in marker_indices if records[index]["exit_code"] == 0
    ]
    if len(successful_markers) != 1:
        raise VerificationError(
            "Gate exit marker was not observed exactly once successfully"
        )
    successful_marker = successful_markers[0]
    if not marker_indices or marker_indices[-1] != successful_marker:
        raise VerificationError("Gate was polled again after its successful marker")
    failed_marker_indices = marker_indices[:-1]
    expected_running_inspects = [index + 1 for index in failed_marker_indices]
    actual_running_inspects = [
        index
        for index, record in enumerate(records)
        if record["argv"] == running_inspect
    ]
    if actual_running_inspects != expected_running_inspects or any(
        records[index]["exit_code"] != 0 for index in actual_running_inspects
    ):
        raise VerificationError(
            "failed Gate marker polls were not paired with running-state checks"
        )
    export_index = argvs.index(gate_export)
    logs = ["docker", "logs", gate_container]
    if argvs.count(logs) != 1:
        raise VerificationError("Gate logs were not captured exactly once")
    logs_index = argvs.index(logs)
    if records[logs_index]["exit_code"] != 0:
        raise VerificationError("Gate log capture was unsuccessful")
    stop = ["docker", "stop", "--time", "1", gate_container]
    if argvs.count(stop) != 1:
        raise VerificationError("Gate was not stopped exactly once")
    stop_index = argvs.index(stop)
    if not successful_marker < logs_index < export_index < stop_index:
        raise VerificationError(
            "Gate marker, log capture, result export, and stop order differs"
        )

    allowed_touching_commands = {
        tuple(marker_poll),
        tuple(running_inspect),
        tuple(gate_export),
        tuple(logs),
        tuple(stop),
        ("docker", "container", "inspect", gate_container),
        ("docker", "rm", "--force", gate_container),
    }
    for argv in argvs:
        touches_gate = any(
            item == gate_container or item.startswith(f"{gate_container}:")
            for item in argv
        )
        if not touches_gate:
            continue
        is_gate_run = (
            argv[:2] == ["docker", "run"]
            and "--name" in argv
            and option_value(argv, "--name") == gate_container
        )
        if not is_gate_run and tuple(argv) not in allowed_touching_commands:
            raise VerificationError(
                "Gate contains an unexpected lifecycle or export command"
            )
    return gate_export


def verify_commands(
    evidence: Path,
    profile: dict[str, Any],
    smoke_image_id: str,
    source_commit: str,
) -> dict[str, str]:
    """Verify the exact build, isolation, mount, execution, and cleanup topology."""
    raw_commands = require_array(
        load_json(evidence / "commands.json", canonical=True), "commands"
    )
    records: list[dict[str, Any]] = []
    argvs: list[list[str]] = []
    for raw in raw_commands:
        record = require_object(raw, "command")
        require_exact_keys(record, {"argv", "cwd", "exit_code"}, "command")
        argv = require_array(record.get("argv"), "command.argv")
        if not argv or any(not isinstance(item, str) for item in argv):
            raise VerificationError("command argv must be a non-empty string array")
        if record.get("cwd") != "$REPO":
            raise VerificationError("command cwd is not the sanitized repository root")
        require_int(record.get("exit_code"), "command.exit_code")
        records.append(record)
        argvs.append(argv)

    def matching(predicate: Any) -> list[list[str]]:
        return [argv for argv in argvs if predicate(argv)]

    def require_once(expected: list[str], label: str) -> None:
        if argvs.count(expected) != 1:
            raise VerificationError(f"campaign did not retain exactly one {label}")

    build_commands = matching(lambda argv: argv[:2] == ["docker", "build"])
    if len(build_commands) != 1:
        raise VerificationError("campaign must contain exactly one Docker build")
    build = build_commands[0]
    smoke_image = option_value(build, "--tag")
    if not smoke_image.startswith("haldir-live-gate-dev-smoke:"):
        raise VerificationError("smoke image tag has the wrong namespace")
    suffix = smoke_image.split(":", maxsplit=1)[1]
    if SUFFIX.fullmatch(suffix) is None:
        raise VerificationError("smoke image tag suffix is malformed")
    expected_build = [
        "docker",
        "build",
        "--progress=plain",
        "--pull",
        "--file",
        "$WORK/source/tools/live-gate-dev-smoke/Dockerfile",
        "--tag",
        smoke_image,
        "$WORK/source",
    ]
    if build != expected_build:
        raise VerificationError(
            "smoke image was not built from the exact source snapshot recipe"
        )
    require_once(
        ["docker", "image", "inspect", "--format", "{{.Id}}", smoke_image],
        "smoke image content-ID resolution",
    )

    names = {
        "gate": f"haldir-gate-bind-{suffix}",
        "inspector": f"haldir-gate-inspect-{suffix}",
        "network": f"haldir-gate-smoke-{suffix}",
        "provision": f"haldir-gate-provision-{suffix}",
        "router": f"haldir-gate-router-{suffix}",
        "smoke_image": smoke_image,
    }
    require_once(["docker", "pull", BUILDER_IMAGE], "pinned builder pull")
    require_once(["docker", "pull", ROUTER_IMAGE], "pinned router pull")
    if (
        argvs.count(["git", "status", "--porcelain=v1"]) != 2
        or argvs.count(["git", "rev-parse", "HEAD"]) != 2
    ):
        raise VerificationError(
            "campaign did not bracket execution with clean-source checks"
        )
    require_once(
        [
            "git",
            "archive",
            "--format=tar",
            "--output=$WORK/source.tar",
            source_commit,
        ],
        "source archive",
    )

    inspector_create = [
        "docker",
        "create",
        "--name",
        names["inspector"],
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        smoke_image_id,
    ]
    require_once(inspector_create, "non-running executable inspector")
    allowed_docker_copies: list[list[str]] = []
    for example, binary in (
        ("live_gate_dev_bind_shutdown", BIND_BINARY),
        ("live_gate_dev_fixture_provision", PROVISION_BINARY),
    ):
        copy = [
            "docker",
            "cp",
            f"{names['inspector']}:{binary}",
            f"$WORK/built-executable-inspection/{example}",
        ]
        allowed_docker_copies.append(copy)
        require_once(copy, f"{example} executable copy")
    if any(
        names["inspector"] in argv
        and argv[:2] in (["docker", "start"], ["docker", "exec"])
        for argv in argvs
    ):
        raise VerificationError("executable inspector container was started")

    provision_runs = matching(
        lambda argv: argv[:2] == ["docker", "run"] and names["provision"] in argv
    )
    if len(provision_runs) != 1:
        raise VerificationError("campaign must contain exactly one provisioner run")
    user = option_value(provision_runs[0], "--user")
    user_match = re.fullmatch(r"([0-9]+):([0-9]+)", user)
    if user_match is None:
        raise VerificationError("provisioner user is not an exact numeric uid:gid")
    uid, gid = user_match.groups()
    owner = f"mode=0700,uid={uid},gid={gid}"
    expected_provision = [
        "docker",
        "run",
        "--detach",
        "--name",
        names["provision"],
        "--network=none",
        "--read-only",
        "--user",
        user,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--tmpfs=/fixture:rw,noexec,nosuid,nodev,size=128m,{owner}",
        f"--tmpfs=/run:rw,noexec,nosuid,nodev,size=1m,{owner}",
        f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,{owner}",
        "--entrypoint",
        "/bin/sh",
        smoke_image_id,
        "-c",
        PROVISION_SCRIPT,
    ]
    if provision_runs[0] != expected_provision:
        raise VerificationError(
            "offline provisioner command differs from the exact sandbox"
        )
    verify_provision_export_commands(records, names["provision"])
    require_once(
        ["docker", "stop", "--time", "1", names["provision"]],
        "provisioner stop",
    )

    require_once(
        ["docker", "network", "create", "--internal", names["network"]],
        "internal network creation",
    )
    launch = require_object(
        load_json(evidence / "configs" / "router-launch.json"), "router launch"
    )
    launch_argv = require_array(launch.get("argv"), "router launch argv")
    if any(not isinstance(item, str) for item in launch_argv):
        raise VerificationError("router launch argv is malformed")
    expected_router = [
        "docker",
        "run",
        "--detach",
        "--name",
        names["router"],
        "--network",
        names["network"],
        "--network-alias",
        "router.haldir.invalid",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--mount",
        f"type=bind,src=$WORK/rendered,dst={RUNTIME_CONFIG_ROOT},readonly",
        "--mount",
        f"type=bind,src=$WORK/router-secrets,dst={RUNTIME_SECRET_ROOT},readonly",
        "--env",
        "RUST_LOG=zenoh_link_tls=debug,zenohd=info",
        ROUTER_IMAGE,
        *launch_argv,
    ]
    require_once(expected_router, "pinned router run")

    expected_gate = [
        "docker",
        "run",
        "--detach",
        "--name",
        names["gate"],
        "--network",
        names["network"],
        "--read-only",
        "--user",
        user,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,{owner}",
        f"--tmpfs=/run:rw,noexec,nosuid,nodev,size=1m,{owner}",
        "--mount",
        "type=bind,src=$WORK/provisioned/gate,dst=/fixture",
        "--mount",
        f"type=bind,src=$WORK/rendered/clients/gate.json,dst={GATE_CONFIG_PATH},readonly",
        "--mount",
        f"type=bind,src=$WORK/gate-secrets,dst={RUNTIME_SECRET_ROOT},readonly",
        f"--tmpfs=/evidence:rw,noexec,nosuid,nodev,size=1m,{owner}",
        "--entrypoint",
        "/bin/sh",
        smoke_image_id,
        "-c",
        BIND_SCRIPT,
    ]
    require_once(expected_gate, "live Gate bind/shutdown run")
    verify_gate_export_commands(records, names["gate"])
    require_once(
        ["docker", "stop", "--time", "1", names["gate"]],
        "Gate stop",
    )
    docker_copy_commands = matching(
        lambda argv: (
            argv[:2] == ["docker", "cp"] or argv[:3] == ["docker", "container", "cp"]
        )
    )
    if sorted(docker_copy_commands) != sorted(allowed_docker_copies):
        raise VerificationError("campaign Docker copy command set differs")
    docker_runs = matching(lambda argv: argv[:2] == ["docker", "run"])
    if sorted(docker_runs) != sorted(
        [expected_provision, expected_router, expected_gate]
    ):
        raise VerificationError(
            "campaign Docker run set differs from provision/router/Gate"
        )

    cleanup_commands = [
        ["docker", "rm", "--force", names["gate"]],
        ["docker", "rm", "--force", names["provision"]],
        ["docker", "rm", "--force", names["router"]],
        ["docker", "rm", "--force", names["inspector"]],
        ["docker", "network", "rm", names["network"]],
        ["docker", "image", "rm", "--force", smoke_image_id],
    ]
    for command in cleanup_commands:
        require_once(command, "cleanup command")
        record = next(item for item in records if item["argv"] == command)
        if record["exit_code"] != 0:
            raise VerificationError("retained cleanup command was unsuccessful")

    allowed_failures = {
        tuple(
            ["docker", "exec", names["provision"], "cat", "/run/haldir-provision-exit"]
        ),
        tuple(["docker", "exec", names["gate"], "cat", "/run/haldir-bind-exit"]),
    }
    for record in records:
        if record["exit_code"] != 0 and tuple(record["argv"]) not in allowed_failures:
            raise VerificationError(
                "campaign contains an unexpected unsuccessful command"
            )
    return {
        **names,
        "smoke_image_id": smoke_image_id,
        "user": user,
        "uid": uid,
        "gid": gid,
    }


def one_inspect(metadata: dict[str, Any], key: str) -> dict[str, Any]:
    values = require_array(metadata.get(key), f"docker metadata {key}")
    if len(values) != 1:
        raise VerificationError(
            f"docker metadata {key} must contain one inspect record"
        )
    return require_object(values[0], f"docker metadata {key} record")


def require_hardened_container(record: dict[str, Any], name: str) -> dict[str, Any]:
    host = require_object(record.get("HostConfig"), f"{name}.HostConfig")
    if host.get("ReadonlyRootfs") is not True:
        raise VerificationError(f"{name} did not use a read-only root filesystem")
    if "ALL" not in require_array(host.get("CapDrop"), f"{name}.CapDrop"):
        raise VerificationError(f"{name} did not drop all capabilities")
    security = require_array(host.get("SecurityOpt"), f"{name}.SecurityOpt")
    if not any(str(item).startswith("no-new-privileges") for item in security):
        raise VerificationError(f"{name} omitted no-new-privileges")
    return host


def bind_mounts(record: dict[str, Any], name: str) -> dict[str, tuple[bool, str]]:
    result: dict[str, tuple[bool, str]] = {}
    for raw in require_array(record.get("Mounts"), f"{name}.Mounts"):
        mount = require_object(raw, f"{name} mount")
        mount_type = mount.get("Type")
        if mount_type == "tmpfs":
            continue
        if mount_type != "bind":
            raise VerificationError(f"{name} contains a non-bind persistent mount")
        destination = mount.get("Destination")
        source = mount.get("Source")
        rw = mount.get("RW")
        if (
            not isinstance(destination, str)
            or not isinstance(source, str)
            or not isinstance(rw, bool)
            or destination in result
        ):
            raise VerificationError(f"{name} bind mount metadata is malformed")
        result[destination] = (rw, source)
    return result


def verify_tmpfs(
    host: dict[str, Any], name: str, expected: dict[str, set[str]]
) -> None:
    tmpfs = require_object(host.get("Tmpfs"), f"{name}.Tmpfs")
    if set(tmpfs) != set(expected):
        raise VerificationError(f"{name} tmpfs destination set differs")
    for destination, required in expected.items():
        value = tmpfs.get(destination)
        if not isinstance(value, str) or not required.issubset(set(value.split(","))):
            raise VerificationError(f"{name} tmpfs options differ at {destination}")


def verify_commands_and_docker(
    evidence: Path, profile: dict[str, Any], manifest: dict[str, Any]
) -> None:
    context = verify_commands(
        evidence,
        profile,
        manifest["smoke_image_id"],
        manifest["source_commit"],
    )
    metadata = require_object(
        load_json(evidence / "logs" / "docker-metadata.json", canonical=True),
        "docker metadata",
    )
    require_exact_keys(
        metadata,
        {
            "builder_image",
            "docker_version",
            "gate_container",
            "inspector_container",
            "provision_container",
            "router_container",
            "router_image",
            "smoke_image",
        },
        "docker metadata",
    )
    require_object(metadata.get("docker_version"), "docker version")
    builder = one_inspect(metadata, "builder_image")
    router_image = one_inspect(metadata, "router_image")
    smoke_image = one_inspect(metadata, "smoke_image")
    for record, pinned in ((builder, BUILDER_IMAGE), (router_image, ROUTER_IMAGE)):
        digest = pinned.rsplit("@", maxsplit=1)[1]
        repo_digests = require_array(record.get("RepoDigests"), "image RepoDigests")
        if not any(str(item).endswith(f"@{digest}") for item in repo_digests):
            raise VerificationError(
                "Docker image inspect omits the requested immutable digest"
            )
    smoke_id = smoke_image.get("Id")
    if not isinstance(smoke_id, str) or smoke_id != manifest["smoke_image_id"]:
        raise VerificationError("smoke image inspect has no image ID")
    if context["smoke_image"] not in require_array(
        smoke_image.get("RepoTags"), "smoke tags"
    ):
        raise VerificationError("smoke image inspect omits the exact generated tag")

    gate = one_inspect(metadata, "gate_container")
    inspector = one_inspect(metadata, "inspector_container")
    provision = one_inspect(metadata, "provision_container")
    router = one_inspect(metadata, "router_container")
    hosts = {
        "gate": require_hardened_container(gate, "gate container"),
        "inspector": require_hardened_container(inspector, "inspector container"),
        "provision": require_hardened_container(provision, "provision container"),
        "router": require_hardened_container(router, "router container"),
    }
    for record, name in (
        (gate, "gate"),
        (inspector, "inspector"),
        (provision, "provision"),
    ):
        if record.get("Image") != smoke_id:
            raise VerificationError(
                f"{name} container is not bound to the inspected smoke image"
            )
    if (
        require_object(gate.get("Config"), "gate.Config").get("Image")
        != context["smoke_image_id"]
    ):
        raise VerificationError(
            "Gate container config does not select the immutable smoke image"
        )
    if (
        require_object(provision.get("Config"), "provision.Config").get("Image")
        != context["smoke_image_id"]
    ):
        raise VerificationError(
            "provision container config does not select the immutable smoke image"
        )
    if (
        require_object(inspector.get("Config"), "inspector.Config").get("Image")
        != context["smoke_image_id"]
    ):
        raise VerificationError(
            "inspector container config does not select the immutable smoke image"
        )
    router_config = require_object(router.get("Config"), "router.Config")
    launch = require_object(
        load_json(evidence / "configs" / "router-launch.json"), "launch"
    )
    if router_config.get("Image") != ROUTER_IMAGE or router_config.get(
        "Cmd"
    ) != launch.get("argv"):
        raise VerificationError(
            "router inspect differs from the pinned image/launch argv"
        )

    if (
        hosts["gate"].get("NetworkMode") != context["network"]
        or hosts["router"].get("NetworkMode") != context["network"]
    ):
        raise VerificationError("Gate and router are not on the one internal network")
    if (
        hosts["provision"].get("NetworkMode") != "none"
        or hosts["inspector"].get("NetworkMode") != "none"
    ):
        raise VerificationError("offline provisioner or inspector had network access")

    owner = {f"uid={context['uid']}", f"gid={context['gid']}", "mode=0700"}
    verify_tmpfs(
        hosts["provision"],
        "provision container",
        {
            "/fixture": {"rw", "noexec", "nosuid", "nodev", "size=128m", *owner},
            "/run": {"rw", "noexec", "nosuid", "nodev", "size=1m", *owner},
            "/tmp": {"rw", "noexec", "nosuid", "nodev", "size=16m", *owner},
        },
    )
    verify_tmpfs(
        hosts["gate"],
        "gate container",
        {
            "/evidence": {"rw", "noexec", "nosuid", "nodev", "size=1m", *owner},
            "/run": {"rw", "noexec", "nosuid", "nodev", "size=1m", *owner},
            "/tmp": {"rw", "noexec", "nosuid", "nodev", "size=16m", *owner},
        },
    )
    verify_tmpfs(
        hosts["router"],
        "router container",
        {"/tmp": {"rw", "noexec", "nosuid", "nodev", "size=16m"}},
    )
    inspector_tmpfs = hosts["inspector"].get("Tmpfs")
    if inspector_tmpfs not in (None, {}):
        raise VerificationError("inspector container unexpectedly used tmpfs state")

    if bind_mounts(provision, "provision container") or bind_mounts(
        inspector, "inspector container"
    ):
        raise VerificationError("offline provisioner or inspector had a bind mount")
    if bind_mounts(router, "router container") != {
        RUNTIME_CONFIG_ROOT: (False, "$WORK/rendered"),
        RUNTIME_SECRET_ROOT: (False, "$WORK/router-secrets"),
    }:
        raise VerificationError("router bind mounts differ from exact read-only inputs")
    if bind_mounts(gate, "gate container") != {
        "/fixture": (True, "$WORK/provisioned/gate"),
        GATE_CONFIG_PATH: (False, "$WORK/rendered/clients/gate.json"),
        RUNTIME_SECRET_ROOT: (False, "$WORK/gate-secrets"),
    }:
        raise VerificationError(
            "Gate mounts differ from exact fixture/config/secret set"
        )

    gate_state = require_object(gate.get("State"), "gate.State")
    provision_state = require_object(provision.get("State"), "provision.State")
    inspector_state = require_object(inspector.get("State"), "inspector.State")
    router_state = require_object(router.get("State"), "router.State")
    if gate_state.get("Status") != "exited" or gate_state.get("Running") is not False:
        raise VerificationError("Gate container was not stopped before metadata capture")
    if (
        provision_state.get("Status") != "exited"
        or provision_state.get("Running") is not False
    ):
        raise VerificationError(
            "provision container was not stopped before metadata capture"
        )
    if (
        inspector_state.get("Status") != "created"
        or inspector_state.get("Running") is not False
    ):
        raise VerificationError(
            "executable inspector was not retained in never-started state"
        )
    if router_state.get("Running") is not True:
        raise VerificationError("router was not running when metadata was captured")
    gate_config = require_object(gate.get("Config"), "gate.Config")
    if gate_config.get("Cmd") != ["-c", BIND_SCRIPT] or gate_config.get(
        "Entrypoint"
    ) != ["/bin/sh"]:
        raise VerificationError(
            "Gate inspect command differs from exact bind wrapper"
        )
    provision_config = require_object(provision.get("Config"), "provision.Config")
    if provision_config.get("Cmd") != ["-c", PROVISION_SCRIPT] or provision_config.get(
        "Entrypoint"
    ) != ["/bin/sh"]:
        raise VerificationError(
            "provision inspect command differs from exact offline script"
        )


def verify_logs(evidence: Path) -> None:
    logs = evidence / "logs"
    provision_stdout = (logs / "provision.stdout.log").read_text(encoding="utf-8")
    provision_stderr = (logs / "provision.stderr.log").read_text(encoding="utf-8")
    bind_stdout = (logs / "bind.stdout.log").read_text(encoding="utf-8")
    bind_stderr = (logs / "bind.stderr.log").read_text(encoding="utf-8")
    router_log = (logs / "router.log").read_text(encoding="utf-8")
    if (
        provision_stdout.strip()
        != ("haldir-live-gate-fixture: OK DEVELOPMENT_ONLY NOT_FOR_PRODUCTION")
        or provision_stderr.strip()
    ):
        raise VerificationError(
            "provision logs do not show one clean development-only success"
        )
    if (
        bind_stdout.strip()
        != (
            "haldir-live-gate-bind: OK DEVELOPMENT_ONLY NOT_FOR_PRODUCTION "
            "zero_intents_processed zero_commands_published"
        )
        or bind_stderr.strip()
    ):
        raise VerificationError(
            "bind logs do not show one clean zero-processing success"
        )
    if not router_log.strip():
        raise VerificationError("router corroboration log is empty")


def verify_readme(evidence: Path, source_commit: str) -> None:
    text = (evidence / "README.md").read_text(encoding="utf-8")
    required = (
        "Development live Gate bind/shutdown generator output",
        f"Generated from clean Haldir commit `{source_commit}`",
        "generator performed no independent verification",
        "processed zero intents and published zero commands",
        "does not prove authenticated control delivery",
        "checks assume a trusted host",
        "abrupt process, host, or daemon loss can require manual cleanup",
    )
    if any(fragment not in text for fragment in required):
        raise VerificationError("README omits the source or honesty boundary")


def verify_evidence(evidence: Path) -> None:
    if evidence.is_symlink() or not evidence.is_dir():
        raise VerificationError(f"evidence directory is absent or unsafe: {evidence}")
    load_and_verify_pins()
    profile = load_profile(DEFAULT_PROFILE)
    expected_configs = set(render_bundle(profile))
    expected_files = {
        "README.md",
        "checksums.sha256",
        "commands.json",
        "manifest.json",
        "pki.json",
        "results/bind-result.json",
        "results/provision-result.json",
        "logs/bind.stderr.log",
        "logs/bind.stdout.log",
        "logs/docker-metadata.json",
        "logs/pki-verification.log",
        "logs/provision.stderr.log",
        "logs/provision.stdout.log",
        "logs/router.log",
    } | {f"configs/{name}" for name in expected_configs}
    actual_files = {
        path.relative_to(evidence).as_posix()
        for path in evidence.rglob("*")
        if path.is_file()
    }
    if actual_files != expected_files:
        raise VerificationError(
            f"artifact file set differs: missing={sorted(expected_files - actual_files)} "
            f"extra={sorted(actual_files - expected_files)}"
        )
    verify_no_secrets_or_host_paths(evidence)
    verify_checksums(evidence)
    configs = verify_configs(evidence, profile)
    provision = verify_provision_result(evidence)
    bind = verify_bind_result(evidence, profile, provision)
    manifest = verify_manifest(evidence, profile, provision, bind, configs)
    verify_pki(evidence, profile)
    verify_commands_and_docker(evidence, profile, manifest)
    verify_logs(evidence)
    verify_readme(evidence, manifest["source_commit"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    args = parser.parse_args()
    try:
        verify_evidence(args.evidence)
    except (VerificationError, OSError, ValueError, KeyError) as error:
        print(f"verify-live-gate-dev-smoke: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "verify-live-gate-dev-smoke: OK "
        "(strict schema, full checksums, exact source/image/config/command bindings)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
