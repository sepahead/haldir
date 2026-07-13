#!/usr/bin/env python3
"""Independently verify retained receiver-observed secure-Zenoh evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_secure_zenoh import BUILDER_IMAGE, EXPECTED_ROUTER_IMAGE, canonical_json  # noqa: E402
from secure_zenoh import DEFAULT_PROFILE, load_profile, render_bundle, verify_bundle  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "evidence" / "11-secure-zenoh-live"
CLAIM_LEDGER = ROOT / "docs" / "CLAIM-LEDGER.md"
PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
HEX_64 = re.compile(r"[0-9a-f]{64}")
HEX_40 = re.compile(r"[0-9a-f]{40}")


class VerificationError(RuntimeError):
    """Evidence is absent, malformed, incomplete, or inconsistent."""


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{name} must be a JSON object")
    return value


def require_array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{name} must be a JSON array")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise VerificationError(
            f"{name} keys differ: missing={sorted(expected - set(value))} "
            f"extra={sorted(set(value) - expected)}"
        )


def load_json(path: Path) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(), object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read strict JSON {path.name}: {error}") from error


def verify_no_secrets_or_host_paths(evidence: Path) -> None:
    for path in evidence.rglob("*"):
        if path.is_symlink():
            raise VerificationError("evidence contains a symbolic link")
        if not path.is_file():
            continue
        if path.name.endswith(".key") or ".key." in path.name:
            raise VerificationError("evidence contains a private-key filename")
        data = path.read_bytes()
        if PRIVATE_KEY_MARKER.search(data):
            raise VerificationError("evidence contains private-key PEM material")
        if b"/Users/" in data or b"/home/" in data or re.search(rb"[A-Za-z]:\\", data):
            raise VerificationError("evidence contains an unsanitized developer-host path")


def verify_checksums(evidence: Path) -> None:
    checksum_path = evidence / "checksums.sha256"
    lines = checksum_path.read_text().splitlines()
    recorded: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if match is None:
            raise VerificationError("checksums.sha256 has a noncanonical line")
        digest, relative = match.groups()
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in recorded:
            raise VerificationError("checksums.sha256 has an unsafe or duplicate path")
        recorded[relative] = digest
    actual_files = {
        path.relative_to(evidence).as_posix()
        for path in evidence.rglob("*")
        if path.is_file() and path.relative_to(evidence).as_posix() != "checksums.sha256"
    }
    if set(recorded) != actual_files:
        raise VerificationError("checksum coverage differs from the retained file set")
    for relative, digest in recorded.items():
        actual = hashlib.sha256((evidence / relative).read_bytes()).hexdigest()
        if actual != digest:
            raise VerificationError(f"checksum mismatch: {relative}")


def verify_configs(evidence: Path, profile: dict[str, Any]) -> None:
    expected = render_bundle(profile)
    config_root = evidence / "configs"
    actual = {
        path.relative_to(config_root).as_posix(): path.read_bytes()
        for path in sorted(config_root.rglob("*"))
        if path.is_file()
    }
    verify_bundle(profile, actual)
    if actual != expected:
        raise VerificationError("retained configs differ from the exact current profile render")

    gate = json.loads(expected["clients/gate.json"])
    tls = gate["transport"]["link"]["tls"]
    tls.pop("connect_certificate", None)
    tls.pop("connect_private_key", None)
    tls["enable_mtls"] = False
    fixture = (evidence / "fixtures" / "no-certificate.json").read_bytes()
    if fixture != canonical_json(gate):
        raise VerificationError(
            "no-certificate fixture is not the exact locally valid no-client-auth derivative"
        )


def expected_attempts(profile: dict[str, Any]) -> dict[str, tuple[str, str, tuple[str, ...], str]]:
    routes = profile["routes"]
    final_route = routes["final_command"]
    intent_a = routes["controller_a_intent"]
    intent_b = routes["controller_b_intent"]
    attempts: dict[str, tuple[str, str, tuple[str, ...], str]] = {
        "controller-a-final-subscribe-denied": (
            "controller-a",
            final_route,
            (),
            "subscribe",
        ),
        "final-positive-pre": (
            "gate",
            final_route,
            ("observer", "robot-crebain"),
            "put",
        ),
        "final-positive-post": (
            "gate",
            final_route,
            ("observer", "robot-crebain"),
            "put",
        ),
        "intent-a-positive-pre": ("controller-a", intent_a, ("gate",), "put"),
        "intent-a-positive-post": ("controller-a", intent_a, ("gate",), "put"),
        "intent-b-positive-pre": ("controller-b", intent_b, ("gate",), "put"),
        "intent-b-positive-post": ("controller-b", intent_b, ("gate",), "put"),
        "intent-a-denied-controller-b": ("controller-b", intent_a, (), "put"),
        "intent-b-denied-controller-a": ("controller-a", intent_b, (), "put"),
    }
    for principal in (
        "admission-authority",
        "controller-a",
        "controller-b",
        "lifecycle",
        "mission-authority",
        "observer",
        "robot-crebain",
    ):
        attempts[f"final-denied-{principal}"] = (principal, final_route, (), "put")
    return attempts


def verify_result(evidence: Path, profile: dict[str, Any]) -> dict[str, Any]:
    result = require_object(load_json(evidence / "result.json"), "result")
    require_exact_keys(
        result,
        {
            "attempts",
            "callback_overflow",
            "denied_case_ids",
            "no_certificate_rejected",
            "observations",
            "quarantine_ms",
            "run_id",
            "schema_version",
            "sessions",
            "status",
        },
        "result",
    )
    if result.get("schema_version") != 1 or result.get("status") != "pass":
        raise VerificationError("result is not a schema-v1 passing campaign")
    if not isinstance(result.get("run_id"), str) or not result["run_id"].startswith(
        "haldir-live-acl-"
    ):
        raise VerificationError("result run_id is malformed")
    if result.get("quarantine_ms") != 2000:
        raise VerificationError("result does not retain the exact two-second quarantine")
    if result.get("no_certificate_rejected") is not True:
        raise VerificationError("certificate-less connection was not rejected")
    if result.get("callback_overflow") is not False:
        raise VerificationError("bounded callback channel overflowed")

    sessions = require_array(result.get("sessions"), "sessions")
    expected_labels = {
        "gate-final-sender",
        "gate-intent-receiver",
        "admission-authority-attacker",
        "controller-a-attacker",
        "controller-b-attacker",
        "lifecycle-attacker",
        "mission-authority-attacker",
        "observer-attacker",
        "robot-crebain-attacker",
        "robot-crebain-final-receiver",
        "observer-final-receiver",
        "controller-a-final-receiver",
    }
    session_objects = [require_object(item, "session") for item in sessions]
    for item in session_objects:
        require_exact_keys(item, {"label", "zid"}, "session")
        if not isinstance(item.get("label"), str) or not isinstance(item.get("zid"), str):
            raise VerificationError("session labels and ZIDs must be strings")
    labels = {item["label"] for item in session_objects}
    zids = {item["zid"] for item in session_objects}
    if len(sessions) != 12 or labels != expected_labels or len(zids) != 12:
        raise VerificationError("session label/ZID inventory is not exactly twelve unique sessions")
    if any(not zid for zid in zids):
        raise VerificationError("one or more session ZIDs are empty")

    expected = expected_attempts(profile)
    attempts = require_array(result.get("attempts"), "attempts")
    by_case: dict[str, dict[str, Any]] = {}
    for raw in attempts:
        item = require_object(raw, "attempt")
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or case_id in by_case:
            raise VerificationError("attempt case IDs must be unique strings")
        operation = item.get("operation")
        exact_keys = {
            "case_id",
            "expected_receivers",
            "local_put_ok",
            "operation",
            "route",
            "sender",
        }
        if operation == "subscribe":
            exact_keys.add("local_declare_ok")
        require_exact_keys(item, exact_keys, f"attempt {case_id}")
        if not all(isinstance(item.get(field), str) for field in ("sender", "route", "operation")):
            raise VerificationError(f"attempt string fields are malformed: {case_id}")
        receivers_value = require_array(item.get("expected_receivers"), "expected_receivers")
        if any(not isinstance(receiver, str) for receiver in receivers_value):
            raise VerificationError(f"attempt receivers are malformed: {case_id}")
        by_case[case_id] = item
    if set(by_case) != set(expected):
        raise VerificationError("attempt matrix differs from the fixed principal/route matrix")
    for case_id, (sender, route, receivers, operation) in expected.items():
        item = by_case[case_id]
        if (
            item.get("sender") != sender
            or item.get("route") != route
            or item.get("operation") != operation
            or tuple(item.get("expected_receivers", [])) != receivers
        ):
            raise VerificationError(f"attempt metadata mismatch: {case_id}")
        if operation == "put" and item.get("local_put_ok") is not True:
            raise VerificationError(f"attempt did not reach a local successful handoff: {case_id}")
        if operation == "subscribe" and (
            item.get("local_put_ok") is not None or item.get("local_declare_ok") is not True
        ):
            raise VerificationError("forbidden subscriber declaration was not exercised")

    routes = profile["routes"]
    expected_observations = {
        (receiver, routes["final_command"], case_id)
        for case_id in ("final-positive-pre", "final-positive-post")
        for receiver in ("observer", "robot-crebain")
    } | {
        ("gate", routes[route_name], case_id)
        for route_name, case_id in (
            ("controller_a_intent", "intent-a-positive-pre"),
            ("controller_a_intent", "intent-a-positive-post"),
            ("controller_b_intent", "intent-b-positive-pre"),
            ("controller_b_intent", "intent-b-positive-post"),
        )
    }
    observations = require_array(result.get("observations"), "observations")
    observation_tuples = []
    for raw in observations:
        item = require_object(raw, "observation")
        require_exact_keys(item, {"case_id", "receiver", "route"}, "observation")
        if not all(isinstance(item.get(field), str) for field in ("case_id", "receiver", "route")):
            raise VerificationError("observation fields must be strings")
        observation_tuples.append((item["receiver"], item["route"], item["case_id"]))
    if len(observation_tuples) != 8 or set(observation_tuples) != expected_observations:
        raise VerificationError("receiver callback set differs from the exact allowlist")

    expected_denied = {case for case, value in expected.items() if not value[2]}
    denied = require_array(result.get("denied_case_ids"), "denied_case_ids")
    if any(not isinstance(case, str) for case in denied):
        raise VerificationError("denied case IDs must be strings")
    if len(denied) != len(expected_denied) or set(denied) != expected_denied:
        raise VerificationError("denied case inventory differs from the fixed matrix")
    if any(case in {observation[2] for observation in observation_tuples} for case in denied):
        raise VerificationError("a denied case reached a receiver callback")
    return result


def verify_pki(evidence: Path, profile: dict[str, Any]) -> None:
    pki = require_object(load_json(evidence / "pki.json"), "pki")
    require_exact_keys(
        pki,
        {
            "ca_sha256_fingerprint",
            "ca_subject",
            "identities",
            "private_keys_retained",
            "schema_version",
        },
        "pki",
    )
    if pki.get("schema_version") != 1 or pki.get("private_keys_retained") is not False:
        raise VerificationError("PKI inventory does not declare ephemeral-key removal")
    identities = require_object(pki.get("identities"), "pki.identities")
    ca_fingerprint = pki.get("ca_sha256_fingerprint")
    if not isinstance(ca_fingerprint, str) or HEX_64.fullmatch(ca_fingerprint) is None:
        raise VerificationError("ephemeral CA fingerprint is malformed")
    expected_cns = {
        "router": profile["router"]["certificate_common_name"],
        **{
            principal_id: principal["certificate_common_name"]
            for principal_id, principal in profile["principals"].items()
        },
    }
    if set(identities) != set(expected_cns):
        raise VerificationError("certificate identity inventory differs from the fixed roles")
    fingerprints = set()
    for identity, common_name in expected_cns.items():
        record = require_object(identities[identity], f"pki identity {identity}")
        require_exact_keys(
            record,
            {"common_name", "purpose", "sha256_fingerprint", "subject_alt_names"},
            f"pki identity {identity}",
        )
        fingerprint = record.get("sha256_fingerprint")
        if record.get("common_name") != common_name or not isinstance(
            fingerprint, str
        ) or HEX_64.fullmatch(fingerprint) is None:
            raise VerificationError(f"certificate binding is malformed: {identity}")
        expected_purpose = "server" if identity == "router" else "client"
        expected_sans = ["DNS:router.haldir.invalid"] if identity == "router" else []
        if record.get("purpose") != expected_purpose or record.get("subject_alt_names") != expected_sans:
            raise VerificationError(f"certificate purpose/SAN mismatch: {identity}")
        fingerprints.add(fingerprint)
    if len(fingerprints) != len(expected_cns):
        raise VerificationError("certificate fingerprints are not globally distinct")
    if ca_fingerprint in fingerprints:
        raise VerificationError("CA and leaf certificate fingerprints collide")

    verification_log = (evidence / "logs" / "pki-verification.log").read_text()
    normalized_log = verification_log.lower().replace(":", "")
    for fingerprint in {ca_fingerprint, *fingerprints}:
        if fingerprint not in normalized_log:
            raise VerificationError("PKI verification log omits a retained fingerprint")
    for common_name in expected_cns.values():
        if common_name not in verification_log:
            raise VerificationError("PKI verification log omits an exact certificate CN")
    if (
        "DNS:router.haldir.invalid" not in verification_log
        or "TLS Web Server Authentication" not in verification_log
        or "TLS Web Client Authentication" not in verification_log
    ):
        raise VerificationError("PKI verification log omits SAN/EKU proof")


def verify_manifest(evidence: Path, profile: dict[str, Any], result: dict[str, Any]) -> None:
    manifest = require_object(load_json(evidence / "manifest.json"), "manifest")
    require_exact_keys(
        manifest,
        {
            "builder_image",
            "cleanup",
            "finished_at_utc",
            "limitations",
            "profile_id",
            "profile_sha256",
            "result_sha256",
            "router_image",
            "schema_version",
            "source_commit",
            "source_dirty",
            "source_snapshot_sha256",
            "started_at_utc",
        },
        "manifest",
    )
    profile_digest = hashlib.sha256(DEFAULT_PROFILE.read_bytes()).hexdigest()
    if (
        manifest.get("schema_version") != 1
        or manifest.get("profile_id") != profile["profile_id"]
        or manifest.get("profile_sha256") != profile_digest
        or manifest.get("builder_image") != BUILDER_IMAGE
        or manifest.get("router_image") != EXPECTED_ROUTER_IMAGE
        or manifest.get("source_dirty") is not False
        or not isinstance(manifest.get("source_commit"), str)
        or HEX_40.fullmatch(manifest["source_commit"]) is None
        or not isinstance(manifest.get("source_snapshot_sha256"), str)
        or HEX_64.fullmatch(manifest["source_snapshot_sha256"]) is None
    ):
        raise VerificationError("manifest source/profile/image binding is inconsistent")
    if manifest.get("result_sha256") != hashlib.sha256(canonical_json(result)).hexdigest():
        raise VerificationError("manifest result digest is inconsistent")
    cleanup = require_object(manifest.get("cleanup"), "manifest.cleanup")
    require_exact_keys(
        cleanup,
        {
            "network_removed",
            "private_material_removed",
            "probe_container_removed",
            "probe_image_removed",
            "router_container_removed",
        },
        "manifest.cleanup",
    )
    if any(value is not True for value in cleanup.values()):
        raise VerificationError("campaign cleanup was incomplete")
    limitations = require_array(manifest.get("limitations"), "manifest.limitations")
    expected_limitations = [
        "stock Zenoh 1.9 combines WebPKI roots with the configured custom CA",
        "the synthetic harness holds all ephemeral client keys in one test container",
        "local put return values are not used as delivery evidence",
        "this does not prove Gate service wiring, credential custody, Crebain application, or complete mediation",
    ]
    if limitations != expected_limitations:
        raise VerificationError("manifest claim limitations differ from the fixed honesty boundary")
    try:
        started = dt.datetime.fromisoformat(str(manifest["started_at_utc"]).replace("Z", "+00:00"))
        finished = dt.datetime.fromisoformat(str(manifest["finished_at_utc"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise VerificationError("manifest timestamps are not ISO-8601 UTC") from error
    if (
        not str(manifest["started_at_utc"]).endswith("Z")
        or not str(manifest["finished_at_utc"]).endswith("Z")
        or finished < started
    ):
        raise VerificationError("manifest timestamp interval is inconsistent")

    archive = subprocess.run(
        ["git", "archive", "--format=tar", manifest["source_commit"]],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if archive.returncode != 0:
        raise VerificationError("manifest source commit is unavailable in the local Git graph")
    if hashlib.sha256(archive.stdout).hexdigest() != manifest["source_snapshot_sha256"]:
        raise VerificationError("manifest source snapshot digest differs from git archive")


def one_inspect(metadata: dict[str, Any], key: str) -> dict[str, Any]:
    values = require_array(metadata.get(key), f"docker metadata {key}")
    if len(values) != 1:
        raise VerificationError(f"docker metadata {key} must contain one inspect record")
    return require_object(values[0], f"docker metadata {key} record")


def require_hardened_container(record: dict[str, Any], name: str) -> None:
    host = require_object(record.get("HostConfig"), f"{name}.HostConfig")
    if host.get("ReadonlyRootfs") is not True:
        raise VerificationError(f"{name} did not use a read-only root filesystem")
    if "ALL" not in require_array(host.get("CapDrop"), f"{name}.CapDrop"):
        raise VerificationError(f"{name} did not drop all Linux capabilities")
    security = require_array(host.get("SecurityOpt"), f"{name}.SecurityOpt")
    if not any(str(item).startswith("no-new-privileges") for item in security):
        raise VerificationError(f"{name} omitted no-new-privileges")
    mounts = require_array(record.get("Mounts"), f"{name}.Mounts")
    for mount in mounts:
        mount_object = require_object(mount, f"{name} mount")
        if mount_object.get("RW") is not False:
            destination = mount_object.get("Destination")
            if destination != "/evidence":
                raise VerificationError(f"{name} has an unexpected writable bind mount")


def verify_commands_and_docker(evidence: Path) -> None:
    commands = require_array(load_json(evidence / "commands.json"), "commands")
    argvs: list[list[str]] = []
    for raw in commands:
        command = require_object(raw, "command")
        require_exact_keys(command, {"argv", "cwd", "exit_code"}, "command")
        argv = require_array(command.get("argv"), "command.argv")
        if not argv or any(not isinstance(part, str) for part in argv):
            raise VerificationError("command argv must be a non-empty string array")
        if not isinstance(command.get("cwd"), str) or command.get("exit_code") != 0:
            raise VerificationError("retained campaign contains an unsuccessful command")
        argvs.append(argv)

    def matching(predicate: Any) -> list[list[str]]:
        return [argv for argv in argvs if predicate(argv)]

    network_commands = matching(
        lambda argv: argv[:4] == ["docker", "network", "create", "--internal"]
    )
    if len(network_commands) != 1 or len(network_commands[0]) != 5:
        raise VerificationError("campaign did not create exactly one internal Docker network")
    network_name = network_commands[0][4]
    if ["docker", "pull", BUILDER_IMAGE] not in argvs or [
        "docker",
        "pull",
        EXPECTED_ROUTER_IMAGE,
    ] not in argvs:
        raise VerificationError("campaign did not pull both immutable input images")

    router_commands = matching(lambda argv: EXPECTED_ROUTER_IMAGE in argv)
    router_runs = [argv for argv in router_commands if argv[:2] == ["docker", "run"]]
    if len(router_runs) != 1:
        raise VerificationError("campaign did not retain exactly one pinned router run")
    router_run = router_runs[0]
    image_index = router_run.index(EXPECTED_ROUTER_IMAGE)
    launch = require_object(
        load_json(evidence / "configs" / "router-launch.json"), "router launch"
    )
    launch_argv = require_array(launch.get("argv"), "router launch argv")
    if router_run[image_index + 1 :] != launch_argv:
        raise VerificationError("router command did not use the exact post-load launch argv")
    required_router_tokens = {
        "--detach",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network-alias",
        "router.haldir.invalid",
    }
    if not required_router_tokens.issubset(router_run) or "--rm" in router_run:
        raise VerificationError("router command omitted required isolation flags")
    if not any(
        f"dst=/etc/haldir-secure-reference-v1" in token and token.endswith(",readonly")
        for token in router_run
    ) or not any(
        f"dst=/run/secrets/haldir-secure-reference-v1" in token
        and token.endswith(",readonly")
        for token in router_run
    ):
        raise VerificationError("router command omitted exact read-only config/secret mounts")

    probe_runs = [
        argv
        for argv in argvs
        if argv[:2] == ["docker", "run"]
        and any(part.startswith("haldir-live-secure-acl-probe:") for part in argv)
    ]
    if len(probe_runs) != 1:
        raise VerificationError("campaign did not retain exactly one named probe run")
    probe_run = probe_runs[0]
    probe_tags = [part for part in probe_run if part.startswith("haldir-live-secure-acl-probe:")]
    if len(probe_tags) != 1:
        raise VerificationError("probe run does not select one derived probe image")
    probe_tag = probe_tags[0]
    if "--rm" in probe_run or not {
        "--name",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "HALDIR_LIVE_ACL_CONFIG_DIR=/campaign",
        "HALDIR_LIVE_ACL_RESULT_PATH=/evidence/result.json",
    }.issubset(probe_run):
        raise VerificationError("probe command omitted its named/hardened/exact-input contract")
    build_commands = matching(lambda argv: argv[:2] == ["docker", "build"])
    expected_build = [
        "docker",
        "build",
        "--pull",
        "--file",
        "$WORK/source/tools/live-secure-zenoh/Dockerfile",
        "--tag",
        probe_tag,
        "$WORK/source",
    ]
    if build_commands != [expected_build]:
        raise VerificationError("probe image was not built once from the immutable source snapshot")

    def option_value(argv: list[str], option: str) -> str:
        positions = [index for index, value in enumerate(argv) if value == option]
        if len(positions) != 1 or positions[0] + 1 >= len(argv):
            raise VerificationError(f"command does not contain exactly one {option}")
        return argv[positions[0] + 1]

    if option_value(router_run, "--network") != network_name or option_value(
        probe_run, "--network"
    ) != network_name:
        raise VerificationError("router/probe commands are not bound to the created internal network")
    probe_mount_tokens = {
        token for token in probe_run if token.startswith("type=bind,")
    }
    probe_destinations = {
        part.removeprefix("dst=")
        for token in probe_mount_tokens
        for part in token.split(",")
        if part.startswith("dst=")
    }
    if probe_destinations != {
        "/run/secrets/haldir-secure-reference-v1",
        "/campaign",
        "/evidence",
    }:
        raise VerificationError("probe command bind-mount destinations differ from the closed set")
    for token in probe_mount_tokens:
        destination = next(
            part.removeprefix("dst=")
            for part in token.split(",")
            if part.startswith("dst=")
        )
        if destination != "/evidence" and not token.endswith(",readonly"):
            raise VerificationError("probe config/secret input mount is not read-only")
        if destination == "/evidence" and token.endswith(",readonly"):
            raise VerificationError("probe evidence output mount is unexpectedly read-only")

    metadata = require_object(
        load_json(evidence / "logs" / "docker-metadata.json"), "docker metadata"
    )
    require_exact_keys(
        metadata,
        {
            "builder_image",
            "docker_version",
            "probe_container",
            "probe_image",
            "router_container",
            "router_image",
        },
        "docker metadata",
    )
    builder = one_inspect(metadata, "builder_image")
    probe_image = one_inspect(metadata, "probe_image")
    router_image = one_inspect(metadata, "router_image")
    for record, digest in (
        (builder, BUILDER_IMAGE.rsplit("@", maxsplit=1)[1]),
        (router_image, EXPECTED_ROUTER_IMAGE.rsplit("@", maxsplit=1)[1]),
    ):
        repo_digests = require_array(record.get("RepoDigests"), "image RepoDigests")
        if not any(str(item).endswith(f"@{digest}") for item in repo_digests):
            raise VerificationError("Docker image inspect does not retain the requested digest")

    router_container = one_inspect(metadata, "router_container")
    probe_container = one_inspect(metadata, "probe_container")
    require_hardened_container(router_container, "router container")
    require_hardened_container(probe_container, "probe container")
    router_config = require_object(router_container.get("Config"), "router container config")
    if (
        router_config.get("Image") != EXPECTED_ROUTER_IMAGE
        or router_config.get("Cmd") != launch_argv
    ):
        raise VerificationError("router container inspect differs from the exact image/argv")
    router_state = require_object(router_container.get("State"), "router container state")
    if router_state.get("Running") is not True:
        raise VerificationError("router was not running when evidence metadata was captured")
    probe_state = require_object(probe_container.get("State"), "probe container state")
    if probe_state.get("ExitCode") != 0 or probe_state.get("Status") != "exited":
        raise VerificationError("probe container did not exit successfully")
    probe_config = require_object(probe_container.get("Config"), "probe container config")
    if probe_config.get("Image") != probe_tag or probe_container.get("Image") != probe_image.get("Id"):
        raise VerificationError("probe build tag/image ID is not bound to the executed container")
    if probe_tag not in require_array(probe_image.get("RepoTags"), "probe image RepoTags"):
        raise VerificationError("probe image inspect omits the built campaign tag")
    for container, name in (
        (router_container, "router container"),
        (probe_container, "probe container"),
    ):
        host = require_object(container.get("HostConfig"), f"{name}.HostConfig")
        if host.get("NetworkMode") != network_name:
            raise VerificationError(f"{name} inspect differs from the internal network")
    router_mounts = {
        require_object(item, "router mount").get("Destination"):
        require_object(item, "router mount").get("RW")
        for item in require_array(router_container.get("Mounts"), "router mounts")
    }
    if router_mounts != {
        "/etc/haldir-secure-reference-v1": False,
        "/run/secrets/haldir-secure-reference-v1": False,
    }:
        raise VerificationError("router inspect mount set differs from exact read-only inputs")
    probe_mounts = {
        require_object(item, "probe mount").get("Destination"):
        require_object(item, "probe mount").get("RW")
        for item in require_array(probe_container.get("Mounts"), "probe mounts")
    }
    if probe_mounts != {
        "/campaign": False,
        "/evidence": True,
        "/run/secrets/haldir-secure-reference-v1": False,
    }:
        raise VerificationError("probe inspect mount set differs from exact inputs/output")


def verify_evidence(evidence: Path) -> None:
    required = {
        "README.md",
        "checksums.sha256",
        "commands.json",
        "manifest.json",
        "pki.json",
        "result.json",
        "logs/docker-metadata.json",
        "logs/pki-verification.log",
        "logs/probe.stderr.log",
        "logs/probe.stdout.log",
        "logs/router.log",
        "fixtures/no-certificate.json",
    }
    actual = {
        path.relative_to(evidence).as_posix()
        for path in evidence.rglob("*")
        if path.is_file()
    }
    if not required.issubset(actual):
        raise VerificationError(f"evidence is missing required files: {sorted(required - actual)}")
    profile = load_profile(DEFAULT_PROFILE)
    verify_no_secrets_or_host_paths(evidence)
    verify_checksums(evidence)
    verify_configs(evidence, profile)
    result = verify_result(evidence, profile)
    verify_pki(evidence, profile)
    verify_manifest(evidence, profile, result)
    verify_commands_and_docker(evidence)
    router_log = (evidence / "logs" / "router.log").read_text()
    if not router_log.strip():
        raise VerificationError("router corroboration log is empty")
    if "peer sent no certificates" not in router_log.lower():
        raise VerificationError("router log does not corroborate no-client-certificate rejection")
    if "CAMPAIGN_PASS" not in (evidence / "logs" / "probe.stdout.log").read_text():
        raise VerificationError("probe stdout lacks its terminal pass marker")


def live_claim_status() -> str:
    for line in CLAIM_LEDGER.read_text().splitlines():
        if line.startswith("| CL-LIVE-TRANSPORT-01 |"):
            fields = [field.strip() for field in line.split("|")]
            if len(fields) >= 5 and fields[3] in {"PROVEN", "UNPROVEN", "OUT OF SCOPE"}:
                return fields[3]
    raise VerificationError("CL-LIVE-TRANSPORT-01 is absent or malformed in the claim ledger")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    evidence = args.evidence or DEFAULT_EVIDENCE
    if not evidence.is_dir():
        if args.evidence is None:
            try:
                status = live_claim_status()
            except (VerificationError, OSError) as error:
                print(f"verify-live-secure-zenoh: FAIL: {error}", file=sys.stderr)
                return 1
            if status != "PROVEN":
                print(
                    "verify-live-secure-zenoh: OK "
                    f"(no retained live evidence; claim status {status})"
                )
                return 0
            print(
                "verify-live-secure-zenoh: FAIL: live claim is PROVEN but evidence is absent",
                file=sys.stderr,
            )
            return 1
        print(f"verify-live-secure-zenoh: FAIL: evidence directory absent: {evidence}", file=sys.stderr)
        return 1
    try:
        verify_evidence(evidence)
    except (VerificationError, OSError, ValueError, KeyError) as error:
        print(f"verify-live-secure-zenoh: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "verify-live-secure-zenoh: OK "
        "(exact command/intent callback subset, pins, PKI inventory, checksums)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
