#!/usr/bin/env python3
"""Run the development-only concrete Gate bind/shutdown smoke.

It builds both feature-gated examples from a clean committed source archive,
provisions a disposable fixture without a network, then opens that fixture in a
different container against the pinned router and immediately shuts the aggregate
down. A successful run emits sanitized generator output below ``target/``; this
generator itself performs neither independent verification nor promotion.
Handled exits remove campaign-named runtime objects and private-key directories;
abrupt process, host, or daemon loss requires manual cleanup of the output root.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any

from live_secure_zenoh import (
    BUILDER_IMAGE,
    EXPECTED_ROUTER_IMAGE,
    RUNTIME_CONFIG_ROOT,
    RUNTIME_SECRET_ROOT,
    CampaignError,
    CommandRunner,
    canonical_json,
    docker_json,
    export_source_snapshot,
    generate_pki,
    require_clean_source,
    require_tools,
    sanitize_text,
    sanitize_value,
    scan_candidate,
    sha256_bytes,
    utc_now,
    wait_for_router,
    write_checksums,
)
from secure_zenoh import load_profile, render_bundle, verify_bundle, write_bundle

ROOT = Path(__file__).resolve().parents[1]
SAFE_OUTPUT_ROOT = (ROOT / "target" / "live-gate-dev-smoke").resolve()
PROVISION_BINARY = "/usr/local/bin/live_gate_dev_fixture_provision"
BIND_BINARY = "/usr/local/bin/live_gate_dev_bind_shutdown"
GATE_CONFIG_PATH = "/etc/haldir-live-gate/gate.json"
GATE_SECRET_FILES = frozenset({"ca.pem", "gate.cert.pem", "gate.key.pem"})
PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
MANIFEST_SCHEMA_VERSION = 2
EXAMPLE_EXECUTABLES = {
    "live_gate_dev_bind_shutdown": BIND_BINARY,
    "live_gate_dev_fixture_provision": PROVISION_BINARY,
}
GENERATOR_ACTIONS = {
    "independent_verification_performed": False,
    "promotion_performed": False,
}

PROVISION_SCRIPT = f"""
set +e
{PROVISION_BINARY} /fixture/gate /fixture/provision-result.json
status=$?
printf '%s\\n' "$status" > /run/haldir-provision-exit
while :; do sleep 3600; done
""".strip()


def require_safe_output(path: Path) -> Path:
    """Confine raw fixtures, logs, and ephemeral credentials to ignored target/."""
    resolved = path.resolve()
    if not resolved.is_relative_to(SAFE_OUTPUT_ROOT):
        raise CampaignError(f"output must be below {SAFE_OUTPUT_ROOT}")
    if resolved.exists():
        raise CampaignError("output already exists; smoke runs never overwrite")
    return resolved


def isolate_gate_secrets(client_mount: Path, work: Path) -> Path:
    """Create the only secret directory exposed to the Gate container."""
    gate_mount = work / "gate-secrets"
    gate_mount.mkdir(mode=stat.S_IRWXU)
    for name in sorted(GATE_SECRET_FILES):
        source = client_mount / name
        if not source.is_file() or source.is_symlink():
            raise CampaignError(f"missing regular Gate secret fixture: {name}")
        shutil.copy2(source, gate_mount / name)
    actual = {path.name for path in gate_mount.iterdir()}
    if actual != GATE_SECRET_FILES:
        raise CampaignError("Gate secret mount contains an unexpected file")
    return gate_mount


def delete_directory(path: Path) -> bool:
    """Best-effort recursive deletion used by independent cleanup actions."""
    try:
        if path.exists() or path.is_symlink():
            if path.is_symlink() or path.is_file():
                path.unlink()
            else:
                shutil.rmtree(path)
        return not path.exists()
    except OSError:
        return False


def remove_private_material(work: Path) -> bool:
    """Delete every directory that may have held an ephemeral private key."""
    outcomes = [
        delete_directory(work / name)
        for name in (
            "pki-authority",
            "router-secrets",
            "client-secrets",
            "gate-secrets",
        )
    ]
    return all(outcomes)


def hash_copied_example_executables(directory: Path) -> dict[str, str]:
    """Hash the exact expected executable copies and reject any shape drift."""
    expected = frozenset(EXAMPLE_EXECUTABLES)
    try:
        actual = {path.name for path in directory.iterdir()}
    except OSError as error:
        raise CampaignError("cannot inspect copied example executables") from error
    if actual != expected:
        raise CampaignError("copied example executable set is not exact")
    hashes: dict[str, str] = {}
    for name in sorted(expected):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise CampaignError(f"copied example is not a regular file: {name}")
        data = path.read_bytes()
        if not data:
            raise CampaignError(f"copied example is empty: {name}")
        hashes[name] = sha256_bytes(data)
    return hashes


def inspect_example_executables(
    runner: CommandRunner,
    *,
    smoke_image: str,
    inspector_container: str,
    work: Path,
) -> dict[str, str]:
    """Copy and hash both executable files from a non-running image container."""
    copies = work / "built-executable-inspection"
    copies.mkdir(mode=stat.S_IRWXU)
    try:
        runner.run(
            [
                "docker",
                "create",
                "--name",
                inspector_container,
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                smoke_image,
            ],
            timeout_seconds=60,
        )
        for name, image_path in sorted(EXAMPLE_EXECUTABLES.items()):
            runner.run(
                [
                    "docker",
                    "cp",
                    f"{inspector_container}:{image_path}",
                    str(copies / name),
                ],
                timeout_seconds=60,
            )
        hashes = hash_copied_example_executables(copies)
    except BaseException:
        delete_directory(copies)
        raise
    if not delete_directory(copies):
        raise CampaignError("could not remove copied example executables")
    return hashes


def resolve_image_id(runner: CommandRunner, image: str) -> str:
    """Resolve a freshly built tag to the immutable local image content ID."""
    image_id = runner.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        timeout_seconds=60,
    ).stdout.strip()
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise CampaignError("built smoke image has no exact local content ID")
    return image_id


def wait_for_provision(runner: CommandRunner, container: str) -> int:
    """Wait for the detached no-network provisioner to publish its exit marker."""
    for _ in range(240):
        marker = runner.run(
            ["docker", "exec", container, "cat", "/run/haldir-provision-exit"],
            check=False,
            timeout_seconds=10,
        )
        if marker.returncode == 0:
            value = marker.stdout.strip()
            if re.fullmatch(r"[0-9]+", value) is None:
                raise CampaignError("provisioner emitted a malformed exit marker")
            return int(value)
        running = runner.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container],
            check=False,
            timeout_seconds=10,
        )
        if running.returncode != 0 or running.stdout.strip() != "true":
            logs = runner.run(["docker", "logs", container], check=False)
            raise CampaignError(
                f"provisioner stopped before reporting status: {logs.stderr[-2000:]}"
            )
        time.sleep(0.25)
    raise CampaignError("provisioner did not finish within 60 seconds")


def validate_result(path: Path, *, provision: bool) -> dict[str, Any]:
    """Validate the narrow result invariants before emitting generator output."""
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise CampaignError(f"cannot read smoke result {path.name}") from error
    if not isinstance(value, dict):
        raise CampaignError(f"smoke result {path.name} is not an object")
    expected_mode = (
        "development-live-fixture-provision-v1"
        if provision
        else "development-live-bind-smoke-v1"
    )
    expected = {
        "development_only": True,
        "mode": expected_mode,
        "ncp_wire_profile": "exact-ncp-v0.8-json",
        "production_claim": False,
        "runtime_profile": "declared-live-zenoh",
        "schema_version": 1,
        "status": "pass",
    }
    for key, required in expected.items():
        if value.get(key) != required:
            raise CampaignError(f"smoke result {path.name} has invalid {key}")
    if provision:
        if value.get("provisioned") is not True:
            raise CampaignError("offline provision result did not report ProvisionNew")
    else:
        negative = value.get("negative_evidence")
        local_returns = value.get("local_returns")
        if value.get("provisioned") is not False:
            raise CampaignError("networked result did not report OpenExisting")
        if not isinstance(negative, dict) or (
            negative.get("intents_processed_by_target") != 0
            or negative.get("commands_published_by_target") != 0
        ):
            raise CampaignError(
                "bind target did not report its zero-processing boundary"
            )
        if local_returns != {
            "aggregate_bind": True,
            "aggregate_shutdown": True,
            "session_open": True,
        }:
            raise CampaignError("bind target did not report all local return values")
    return value


def cleanup_runtime(
    runner: CommandRunner,
    *,
    inspector_container: str,
    provision_container: str,
    gate_container: str,
    router_container: str,
    network: str,
    smoke_image: str,
) -> dict[str, bool]:
    """Remove every campaign-named runtime Docker object, isolating failures."""
    actions = (
        ("gate_container_removed", ["docker", "rm", "--force", gate_container]),
        (
            "provision_container_removed",
            ["docker", "rm", "--force", provision_container],
        ),
        ("router_container_removed", ["docker", "rm", "--force", router_container]),
        (
            "inspector_container_removed",
            ["docker", "rm", "--force", inspector_container],
        ),
        ("network_removed", ["docker", "network", "rm", network]),
        ("smoke_image_removed", ["docker", "image", "rm", "--force", smoke_image]),
    )
    outcomes: dict[str, bool] = {}
    for label, argv in actions:
        try:
            result = runner.run(argv, check=False, timeout_seconds=30)
            outcomes[label] = result.returncode == 0
        except BaseException:
            outcomes[label] = False
    return outcomes


def build_candidate(
    *,
    work: Path,
    source_commit: str,
    source_snapshot_sha256: str,
    profile: dict[str, Any],
    profile_bytes: bytes,
    started_at: str,
    finished_at: str,
    cleanup: dict[str, bool],
    private_cleanup: bool,
    fixture_cleanup: bool,
    example_executable_sha256: dict[str, str],
    smoke_image_id: str,
    commands: list[dict[str, Any]],
    pki_inventory: dict[str, Any],
    pki_log: str,
    docker_metadata: dict[str, Any],
) -> Path:
    """Create sanitized generator output below target/."""
    evidence = work / "evidence"
    evidence.mkdir()
    shutil.copytree(work / "rendered", evidence / "configs")
    results = evidence / "results"
    results.mkdir()
    for name in ("provision-result.json", "bind-result.json"):
        value = json.loads((work / "raw" / name).read_bytes())
        (results / name).write_bytes(canonical_json(value))
    logs = evidence / "logs"
    logs.mkdir()
    for name in (
        "provision.stdout.log",
        "provision.stderr.log",
        "bind.stdout.log",
        "bind.stderr.log",
        "router.log",
    ):
        source = work / "raw" / name
        (logs / name).write_text(sanitize_text(source.read_text(), work))
    (logs / "pki-verification.log").write_text(sanitize_text(pki_log, work))
    (logs / "docker-metadata.json").write_bytes(
        canonical_json(sanitize_value(docker_metadata, work))
    )
    (evidence / "commands.json").write_bytes(canonical_json(commands))
    pki_inventory = dict(pki_inventory)
    pki_inventory["mounted_secret_sets"] = {
        "gate": sorted(GATE_SECRET_FILES),
        "router": ["ca.pem", "router.cert.pem", "router.key.pem"],
    }
    (evidence / "pki.json").write_bytes(canonical_json(pki_inventory))

    provision = json.loads((work / "raw" / "provision-result.json").read_bytes())
    bind = json.loads((work / "raw" / "bind-result.json").read_bytes())
    if frozenset(example_executable_sha256) != frozenset(EXAMPLE_EXECUTABLES) or any(
        re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for digest in example_executable_sha256.values()
    ):
        raise CampaignError("example executable digest set is invalid")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", smoke_image_id) is None:
        raise CampaignError("smoke image ID is invalid")
    manifest = {
        "builder_image": BUILDER_IMAGE,
        "cargo_lock_sha256": sha256_bytes(
            (work / "source" / "Cargo.lock").read_bytes()
        ),
        "cleanup": {
            **cleanup,
            "private_material_removed": private_cleanup,
            "raw_fixture_removed": fixture_cleanup,
        },
        "examples": [
            "live_gate_dev_fixture_provision",
            "live_gate_dev_bind_shutdown",
        ],
        "example_executable_sha256": dict(sorted(example_executable_sha256.items())),
        "finished_at_utc": finished_at,
        "fixture_transition": "ProvisionNew-offline-then-OpenExisting-live",
        "dockerfile_sha256": sha256_bytes(
            (
                work / "source" / "tools" / "live-gate-dev-smoke" / "Dockerfile"
            ).read_bytes()
        ),
        "gate_config_sha256": sha256_bytes(
            (work / "rendered" / "clients" / "gate.json").read_bytes()
        ),
        "generator_actions": dict(GENERATOR_ACTIONS),
        "limitations": [
            "the generator performs no independent verification or evidence promotion",
            "the bind target processes zero intents and publishes zero commands",
            "local bind and shutdown returns do not prove delivery or remote cleanup",
            "the fixture uses local-rewritable development state and deterministic public test keys",
            "ephemeral test PKI and disposable containers do not prove production credential custody",
            "the cooperative lock and path checks assume a trusted host",
            "abrupt process, host, or daemon loss can require manual cleanup; build cache is not campaign evidence",
        ],
        "profile_id": profile["profile_id"],
        "profile_sha256": sha256_bytes(profile_bytes),
        "provision_result_sha256": sha256_bytes(canonical_json(provision)),
        "router_image": profile["router"]["image"],
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "source_commit": source_commit,
        "source_dirty": False,
        "source_snapshot_sha256": source_snapshot_sha256,
        "smoke_image_id": smoke_image_id,
        "started_at_utc": started_at,
        "bind_result_sha256": sha256_bytes(canonical_json(bind)),
    }
    if manifest["router_image"] != EXPECTED_ROUTER_IMAGE:
        raise CampaignError("router image changed during smoke run")
    (evidence / "manifest.json").write_bytes(canonical_json(manifest))
    (evidence / "README.md").write_text(
        "# Development live Gate bind/shutdown generator output\n\n"
        f"Generated from clean Haldir commit `{source_commit}`. The offline container "
        "provisioned a disposable tmpfs fixture, and a separate container opened that "
        "fixture, opened one strict session against the pinned router, bound the real "
        "aggregate, and immediately shut it down.\n\n"
        "The generator performed no independent verification and does not decide "
        "retention or promotion; those actions and any claim status must be established "
        "externally. The target processed zero intents and published zero commands. It "
        "does not prove authenticated control delivery, publication, credential custody, "
        "remote cleanup, production shutdown, or complete mediation. The cooperative path "
        "checks assume a trusted host; abrupt process, host, or daemon loss can require "
        "manual cleanup of campaign-named objects and the generator output root.\n"
    )
    write_checksums(evidence)
    scan_candidate(evidence)
    for path in evidence.rglob("*"):
        if path.is_file() and PRIVATE_KEY_MARKER.search(path.read_bytes()):
            raise CampaignError("generator output contains private-key material")
    return evidence


def run_smoke(output: Path) -> Path:
    """Run the split provision/bind smoke and return the output directory."""
    require_tools()
    work = require_safe_output(output)
    work.mkdir(parents=True, mode=stat.S_IRWXU)
    raw = work / "raw"
    raw.mkdir(mode=stat.S_IRWXU)
    runner = CommandRunner(work)
    started_at = utc_now()
    source_commit = require_clean_source(runner)
    source_root, source_snapshot_sha256 = export_source_snapshot(
        runner, source_commit, work
    )
    source_profile_path = (
        source_root / "deploy" / "secure-reference-v1" / "profile.json"
    )
    profile_bytes = source_profile_path.read_bytes()
    profile = load_profile(source_profile_path)
    if profile["router"]["image"] != EXPECTED_ROUTER_IMAGE:
        raise CampaignError("source profile no longer uses the reviewed router image")
    rendered_files = render_bundle(profile)
    verify_bundle(profile, rendered_files)
    rendered = work / "rendered"
    write_bundle(rendered, rendered_files)

    suffix = secrets.token_hex(6)
    network = f"haldir-gate-smoke-{suffix}"
    provision_container = f"haldir-gate-provision-{suffix}"
    router_container = f"haldir-gate-router-{suffix}"
    gate_container = f"haldir-gate-bind-{suffix}"
    inspector_container = f"haldir-gate-inspect-{suffix}"
    smoke_image = f"haldir-live-gate-dev-smoke:{suffix}"
    cleanup: dict[str, bool] = {}
    private_cleanup = False
    fixture_cleanup = False
    error: BaseException | None = None
    docker_metadata: dict[str, Any] = {}
    example_executable_sha256: dict[str, str] = {}
    smoke_image_id = ""
    pki_inventory: dict[str, Any] = {}
    pki_log = ""
    provisioned = work / "provisioned"
    uid = os.getuid()
    gid = os.getgid()
    user = f"{uid}:{gid}"
    owner_options = f"mode=0700,uid={uid},gid={gid}"

    try:
        runner.run(["docker", "pull", BUILDER_IMAGE], timeout_seconds=300)
        runner.run(["docker", "pull", EXPECTED_ROUTER_IMAGE], timeout_seconds=300)
        dockerfile = source_root / "tools" / "live-gate-dev-smoke" / "Dockerfile"
        runner.run(
            [
                "docker",
                "build",
                "--pull",
                "--file",
                str(dockerfile),
                "--tag",
                smoke_image,
                str(source_root),
            ],
            timeout_seconds=1200,
        )
        smoke_image_id = resolve_image_id(runner, smoke_image)
        example_executable_sha256 = inspect_example_executables(
            runner,
            smoke_image=smoke_image_id,
            inspector_container=inspector_container,
            work=work,
        )

        runner.run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                provision_container,
                "--network=none",
                "--read-only",
                "--user",
                user,
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                f"--tmpfs=/fixture:rw,noexec,nosuid,nodev,size=128m,{owner_options}",
                f"--tmpfs=/run:rw,noexec,nosuid,nodev,size=1m,{owner_options}",
                f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,{owner_options}",
                "--entrypoint",
                "/bin/sh",
                smoke_image_id,
                "-c",
                PROVISION_SCRIPT,
            ],
            timeout_seconds=60,
        )
        provision_exit = wait_for_provision(runner, provision_container)
        provision_logs = runner.run(
            ["docker", "logs", provision_container], check=False, timeout_seconds=30
        )
        (raw / "provision.stdout.log").write_text(provision_logs.stdout)
        (raw / "provision.stderr.log").write_text(provision_logs.stderr)
        if provision_exit != 0:
            raise CampaignError(
                f"offline provisioner failed with exit code {provision_exit}"
            )
        provisioned.mkdir(mode=stat.S_IRWXU)
        runner.run(
            ["docker", "cp", f"{provision_container}:/fixture/.", str(provisioned)],
            timeout_seconds=60,
        )
        shutil.copy2(
            provisioned / "provision-result.json", raw / "provision-result.json"
        )
        validate_result(raw / "provision-result.json", provision=True)
        runner.run(
            ["docker", "stop", "--time", "1", provision_container],
            timeout_seconds=30,
        )

        router_mount, client_mount, pki_inventory, pki_log = generate_pki(
            runner, profile, work
        )
        gate_mount = isolate_gate_secrets(client_mount, work)
        shortened_key_lifetime = [
            delete_directory(work / "pki-authority"),
            delete_directory(client_mount),
        ]
        if not all(shortened_key_lifetime):
            raise CampaignError("could not shorten non-runtime private-key lifetime")

        runner.run(
            ["docker", "network", "create", "--internal", network],
            timeout_seconds=60,
        )
        launch = json.loads((rendered / "router-launch.json").read_bytes())
        router_argv = launch.get("argv")
        if not isinstance(router_argv, list) or not all(
            isinstance(item, str) for item in router_argv
        ):
            raise CampaignError("router launch argv is malformed")
        runner.run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                router_container,
                "--network",
                network,
                "--network-alias",
                "router.haldir.invalid",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
                "--mount",
                f"type=bind,src={rendered},dst={RUNTIME_CONFIG_ROOT},readonly",
                "--mount",
                f"type=bind,src={router_mount},dst={RUNTIME_SECRET_ROOT},readonly",
                "--env",
                "RUST_LOG=zenoh_link_tls=debug,zenohd=info",
                EXPECTED_ROUTER_IMAGE,
                *router_argv,
            ],
            timeout_seconds=60,
        )
        wait_for_router(runner, router_container)

        gate_config = rendered / "clients" / "gate.json"
        fixture = provisioned / "gate"
        gate = runner.run(
            [
                "docker",
                "run",
                "--name",
                gate_container,
                "--network",
                network,
                "--read-only",
                "--user",
                user,
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,{owner_options}",
                "--mount",
                f"type=bind,src={fixture},dst=/fixture",
                "--mount",
                f"type=bind,src={gate_config},dst={GATE_CONFIG_PATH},readonly",
                "--mount",
                f"type=bind,src={gate_mount},dst={RUNTIME_SECRET_ROOT},readonly",
                f"--tmpfs=/evidence:rw,noexec,nosuid,nodev,size=1m,{owner_options}",
                smoke_image_id,
                BIND_BINARY,
                "/fixture",
                GATE_CONFIG_PATH,
                "/evidence/bind-result.json",
            ],
            check=False,
            timeout_seconds=180,
        )
        (raw / "bind.stdout.log").write_text(gate.stdout)
        (raw / "bind.stderr.log").write_text(gate.stderr)
        router_logs = runner.run(
            ["docker", "logs", router_container], check=False, timeout_seconds=60
        )
        (raw / "router.log").write_text(router_logs.stdout + router_logs.stderr)
        bind_result_copy = runner.run(
            [
                "docker",
                "cp",
                f"{gate_container}:/evidence/bind-result.json",
                str(raw / "bind-result.json"),
            ],
            check=False,
            timeout_seconds=60,
        )
        if gate.returncode != 0:
            raise CampaignError(
                f"bind/shutdown target failed with exit code {gate.returncode}"
            )
        if bind_result_copy.returncode != 0:
            raise CampaignError("bind/shutdown target produced no copyable result")
        validate_result(raw / "bind-result.json", provision=False)

        docker_metadata = {
            "builder_image": docker_json(runner, ["image", "inspect", BUILDER_IMAGE]),
            "docker_version": docker_json(
                runner, ["version", "--format", "{{json .}}"]
            ),
            "gate_container": docker_json(
                runner, ["container", "inspect", gate_container]
            ),
            "inspector_container": docker_json(
                runner, ["container", "inspect", inspector_container]
            ),
            "provision_container": docker_json(
                runner, ["container", "inspect", provision_container]
            ),
            "router_container": docker_json(
                runner, ["container", "inspect", router_container]
            ),
            "router_image": docker_json(
                runner, ["image", "inspect", EXPECTED_ROUTER_IMAGE]
            ),
            "smoke_image": docker_json(runner, ["image", "inspect", smoke_image_id]),
        }
        if require_clean_source(runner) != source_commit:
            raise CampaignError("source HEAD changed while the immutable snapshot ran")
    except BaseException as caught:
        error = caught
    finally:
        try:
            cleanup = cleanup_runtime(
                runner,
                inspector_container=inspector_container,
                provision_container=provision_container,
                gate_container=gate_container,
                router_container=router_container,
                network=network,
                smoke_image=smoke_image_id or smoke_image,
            )
        finally:
            private_cleanup = remove_private_material(work)
            fixture_cleanup = delete_directory(provisioned)
        (raw / "commands.json").write_bytes(canonical_json(runner.commands))

    if error is not None:
        if isinstance(error, Exception):
            raise CampaignError(
                f"live Gate smoke failed after cleanup: {error}"
            ) from error
        raise error
    if not all(cleanup.values()) or not private_cleanup or not fixture_cleanup:
        raise CampaignError("smoke passed but disposable cleanup was incomplete")
    finished_at = utc_now()
    return build_candidate(
        work=work,
        source_commit=source_commit,
        source_snapshot_sha256=source_snapshot_sha256,
        profile=profile,
        profile_bytes=profile_bytes,
        started_at=started_at,
        finished_at=finished_at,
        cleanup=cleanup,
        private_cleanup=private_cleanup,
        fixture_cleanup=fixture_cleanup,
        example_executable_sha256=example_executable_sha256,
        smoke_image_id=smoke_image_id,
        commands=runner.commands,
        pki_inventory=pki_inventory,
        pki_log=pki_log,
        docker_metadata=docker_metadata,
    )


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = run_smoke(args.output)
    except (CampaignError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"run-live-gate-dev-smoke: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"run-live-gate-dev-smoke: OK (generator output: {evidence})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
