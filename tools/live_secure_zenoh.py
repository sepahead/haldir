#!/usr/bin/env python3
"""Run the pinned current-profile receiver-observed Zenoh ACL campaign.

The live run is deliberately separate from the offline CI gate. It creates ephemeral
test identities below an ignored target directory, starts the exact pinned router,
runs the Rust campaign in a pinned builder image on an internal Docker network, and
emits a sanitized candidate evidence directory. Normal and handled-error paths make
private-key deletion mandatory; incomplete cleanup prevents evidence publication.
SIGKILL or host/daemon failure still requires operator cleanup of the raw run directory.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

from secure_zenoh import load_profile, render_bundle, verify_bundle, write_bundle

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "deploy" / "secure-reference-v1" / "profile.json"
SAFE_OUTPUT_ROOT = (ROOT / "target" / "live-secure-zenoh").resolve()
BUILDER_IMAGE = (
    "docker.io/library/rust@"
    "sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc"
)
EXPECTED_ROUTER_IMAGE = (
    "docker.io/eclipse/zenoh@"
    "sha256:157965d71e0bfd0a044d76a985ff0e5c306ad3968929168fb9678cd2a7fec23f"
)
RUNTIME_CONFIG_ROOT = "/etc/haldir-secure-reference-v1"
RUNTIME_SECRET_ROOT = "/run/secrets/haldir-secure-reference-v1"
PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")


class CampaignError(RuntimeError):
    """A live campaign precondition or command failed."""


def canonical_json(value: Any) -> bytes:
    """Return stable human-readable JSON bytes."""
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    """Return a second-resolution UTC timestamp."""
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def require_safe_output(path: Path) -> Path:
    """Restrict raw campaign output, including private keys, to ignored target/."""
    resolved = path.resolve()
    if not resolved.is_relative_to(SAFE_OUTPUT_ROOT):
        raise CampaignError(f"output must be below {SAFE_OUTPUT_ROOT}")
    if resolved.exists():
        raise CampaignError("output already exists; live campaigns never overwrite a run")
    return resolved


def sanitize_text(text: str, work: Path) -> str:
    """Remove host-specific absolute paths from retained evidence."""
    return text.replace(str(work), "$WORK").replace(str(ROOT), "$REPO")


def sanitize_value(value: Any, work: Path) -> Any:
    """Recursively sanitize strings in Docker/command metadata."""
    if isinstance(value, str):
        return sanitize_text(value, work)
    if isinstance(value, list):
        return [sanitize_value(item, work) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitize_value(item, work) for key, item in value.items()}
    return value


class CommandRunner:
    """Capture exact subprocess commands without invoking a shell."""

    def __init__(self, work: Path) -> None:
        self.work = work
        self.commands: list[dict[str, Any]] = []

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
        input_text: str | None = None,
        timeout_seconds: int | float = 120,
    ) -> subprocess.CompletedProcess[str]:
        try:
            process = subprocess.run(
                argv,
                cwd=cwd,
                check=False,
                capture_output=True,
                text=True,
                input=input_text,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            self.commands.append(
                {
                    "argv": sanitize_value(argv, self.work),
                    "cwd": sanitize_text(str(cwd or ROOT), self.work),
                    "exit_code": "timeout",
                    "timeout_seconds": timeout_seconds,
                }
            )
            raise CampaignError(
                f"command timed out after {timeout_seconds}s: {argv[0]}"
            ) from error
        self.commands.append(
            {
                "argv": sanitize_value(argv, self.work),
                "cwd": sanitize_text(str(cwd or ROOT), self.work),
                "exit_code": process.returncode,
            }
        )
        if check and process.returncode != 0:
            stderr = sanitize_text(process.stderr[-4000:], self.work)
            raise CampaignError(f"command failed ({process.returncode}): {argv[0]}: {stderr}")
        return process

    def run_bytes(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
        max_stdout_bytes: int,
        timeout_seconds: int = 120,
    ) -> subprocess.CompletedProcess[bytes]:
        """Run a command while enforcing a hard in-memory stdout bound."""
        if max_stdout_bytes <= 0:
            raise ValueError("max_stdout_bytes must be positive")
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None or process.stderr is None:
            process.kill()
            process.wait()
            raise CampaignError("binary command pipes could not be created")
        streams = selectors.DefaultSelector()
        streams.register(process.stdout, selectors.EVENT_READ, "stdout")
        streams.register(process.stderr, selectors.EVENT_READ, "stderr")
        stdout = bytearray()
        stderr_tail = bytearray()
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        stdout_limit_exceeded = False

        def kill_process() -> None:
            try:
                process.kill()
            except ProcessLookupError:
                pass

        try:
            while streams.get_map():
                if not timed_out and not stdout_limit_exceeded:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        kill_process()
                        remaining = None
                else:
                    remaining = None
                events = streams.select(remaining)
                if not events:
                    timed_out = True
                    kill_process()
                    continue
                for key, _ in events:
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        streams.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if key.data == "stdout":
                        available = max_stdout_bytes - len(stdout)
                        if len(chunk) > available:
                            stdout.extend(chunk[: max(available, 0)])
                            stdout_limit_exceeded = True
                            kill_process()
                        else:
                            stdout.extend(chunk)
                    else:
                        stderr_tail.extend(chunk)
                        del stderr_tail[:-4000]
            returncode = process.wait()
        finally:
            streams.close()
            if process.poll() is None:
                kill_process()
                process.wait()

        command = {
            "argv": sanitize_value(argv, self.work),
            "cwd": sanitize_text(str(cwd or ROOT), self.work),
        }
        if timed_out:
            self.commands.append(
                {
                    **command,
                    "exit_code": "timeout",
                    "timeout_seconds": timeout_seconds,
                }
            )
            raise CampaignError(
                f"command timed out after {timeout_seconds}s: {argv[0]}"
            )
        if stdout_limit_exceeded:
            self.commands.append(
                {
                    **command,
                    "exit_code": "stdout-limit",
                    "max_stdout_bytes": max_stdout_bytes,
                }
            )
            raise CampaignError(
                f"command stdout exceeded {max_stdout_bytes} bytes: {argv[0]}"
            )
        self.commands.append(
            {
                **command,
                "exit_code": returncode,
            }
        )
        if check and returncode != 0:
            stderr = sanitize_text(
                bytes(stderr_tail).decode("utf-8", errors="replace"), self.work
            )
            raise CampaignError(
                f"command failed ({returncode}): {argv[0]}: {stderr}"
            )
        return subprocess.CompletedProcess(
            argv,
            returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr_tail),
        )


def require_clean_source(runner: CommandRunner) -> str:
    """Return HEAD only when the committed source tree is clean."""
    status = runner.run(["git", "status", "--porcelain=v1"], cwd=ROOT).stdout
    if status.strip():
        raise CampaignError("campaign requires a clean committed worktree")
    head = runner.run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise CampaignError("cannot resolve an exact source commit")
    return head


def export_source_snapshot(
    runner: CommandRunner, commit: str, work: Path
) -> tuple[Path, str]:
    """Export the exact committed tree used for rendering and the probe build."""
    archive = work / "source.tar"
    source = work / "source"
    runner.run(
        ["git", "archive", "--format=tar", f"--output={archive}", commit],
        cwd=ROOT,
    )
    archive_digest = sha256_bytes(archive.read_bytes())
    source.mkdir()
    with tarfile.open(archive, mode="r:") as bundle:
        bundle.extractall(source, filter="data")
    archive.unlink()
    return source, archive_digest


def require_tools() -> None:
    """Fail before mutation if required local tools are absent."""
    missing = [name for name in ("docker", "git", "openssl") if shutil.which(name) is None]
    if missing:
        raise CampaignError(f"missing required tools: {', '.join(missing)}")


def write_no_certificate_config(rendered: Path, campaign: Path) -> None:
    """Derive an intentionally certificate-less raw Zenoh client fixture."""
    gate = json.loads((rendered / "clients" / "gate.json").read_text())
    tls = gate.get("transport", {}).get("link", {}).get("tls", {})
    if not isinstance(tls, dict):
        raise CampaignError("rendered Gate TLS configuration is malformed")
    tls.pop("connect_certificate", None)
    tls.pop("connect_private_key", None)
    # This intentionally bypasses the strict Haldir client validator. It leaves
    # CA/name verification active but asks Zenoh for a locally valid TLS client
    # without client authentication, so rejection occurs at the router mTLS
    # handshake rather than during local config construction.
    tls["enable_mtls"] = False
    campaign.mkdir(parents=True)
    shutil.copytree(rendered / "clients", campaign / "clients")
    (campaign / "no-certificate.json").write_bytes(canonical_json(gate))


def openssl(
    runner: CommandRunner,
    argv: list[str],
    log: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run OpenSSL and retain public verification output only."""
    process = runner.run(["openssl", *argv], check=check)
    safe_argv = [part for part in argv if not part.endswith(".key.pem")]
    log.append(f"$ openssl {' '.join(safe_argv)}\n")
    if process.stdout:
        log.append(process.stdout)
    if process.stderr and not any(token in argv for token in ("req", "x509")):
        log.append(process.stderr)
    return process


def generate_pki(
    runner: CommandRunner, profile: dict[str, Any], work: Path
) -> tuple[Path, Path, dict[str, Any], str]:
    """Generate and verify short-lived test identities; return isolated mount roots."""
    authority = work / "pki-authority"
    router_mount = work / "router-secrets"
    client_mount = work / "client-secrets"
    authority.mkdir()
    router_mount.mkdir()
    client_mount.mkdir()
    log: list[str] = []

    ca_key = authority / "ca.key.pem"
    ca_cert = authority / "ca.pem"
    openssl(
        runner,
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=haldir-live-campaign-ephemeral-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
        ],
        log,
    )
    os.chmod(ca_key, stat.S_IRUSR)

    identities: list[tuple[str, str, str]] = [
        (
            "router",
            profile["router"]["certificate_common_name"],
            "server",
        )
    ]
    for principal_id, principal in sorted(profile["principals"].items()):
        identities.append((principal_id, principal["certificate_common_name"], "client"))

    inventory: dict[str, Any] = {
        "ca_sha256_fingerprint": "",
        "ca_subject": "CN=haldir-live-campaign-ephemeral-ca",
        "identities": {},
        "private_keys_retained": False,
        "schema_version": 1,
    }
    ca_details = openssl(
        runner,
        [
            "x509",
            "-in",
            str(ca_cert),
            "-noout",
            "-subject",
            "-fingerprint",
            "-sha256",
        ],
        log,
    ).stdout
    ca_fingerprint_match = re.search(
        r"sha256 Fingerprint=([0-9A-F:]+)", ca_details, re.IGNORECASE
    )
    if ca_fingerprint_match is None:
        raise CampaignError("cannot parse ephemeral CA fingerprint")
    inventory["ca_sha256_fingerprint"] = (
        ca_fingerprint_match.group(1).replace(":", "").lower()
    )
    serial_created = False
    for identity, common_name, purpose in identities:
        key = authority / f"{identity}.key.pem"
        csr = authority / f"{identity}.csr.pem"
        cert = authority / f"{identity}.cert.pem"
        ext = authority / f"{identity}.ext"
        extensions = [
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            f"extendedKeyUsage={'serverAuth' if purpose == 'server' else 'clientAuth'}",
        ]
        if purpose == "server":
            extensions.append("subjectAltName=DNS:router.haldir.invalid")
        ext.write_text("\n".join(extensions) + "\n")
        openssl(
            runner,
            [
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-subj",
                f"/CN={common_name}",
                "-keyout",
                str(key),
                "-out",
                str(csr),
            ],
            log,
        )
        os.chmod(key, stat.S_IRUSR)
        sign_args = [
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-sha256",
            "-days",
            "1",
            "-extfile",
            str(ext),
            "-out",
            str(cert),
        ]
        if not serial_created:
            sign_args.append("-CAcreateserial")
            serial_created = True
        else:
            sign_args.extend(["-CAserial", str(authority / "ca.srl")])
        openssl(runner, sign_args, log)

        verify_args = ["verify", "-CAfile", str(ca_cert)]
        if purpose == "server":
            verify_args.extend(
                ["-purpose", "sslserver", "-verify_hostname", "router.haldir.invalid"]
            )
        else:
            verify_args.extend(["-purpose", "sslclient"])
        verify_args.append(str(cert))
        openssl(runner, verify_args, log)
        openssl(runner, ["x509", "-in", str(cert), "-checkend", "3600", "-noout"], log)
        details = openssl(
            runner,
            [
                "x509",
                "-in",
                str(cert),
                "-noout",
                "-subject",
                "-issuer",
                "-fingerprint",
                "-sha256",
                "-dates",
            ],
            log,
        ).stdout
        openssl(
            runner,
            [
                "x509",
                "-in",
                str(cert),
                "-noout",
                "-ext",
                "subjectAltName,extendedKeyUsage",
            ],
            log,
        )
        fingerprint_match = re.search(r"sha256 Fingerprint=([0-9A-F:]+)", details, re.IGNORECASE)
        if fingerprint_match is None:
            raise CampaignError(f"cannot parse certificate fingerprint for {identity}")
        inventory["identities"][identity] = {
            "common_name": common_name,
            "purpose": purpose,
            "sha256_fingerprint": fingerprint_match.group(1).replace(":", "").lower(),
            "subject_alt_names": ["DNS:router.haldir.invalid"] if purpose == "server" else [],
        }

        mount = router_mount if purpose == "server" else client_mount
        shutil.copy2(cert, mount / f"{identity}.cert.pem")
        shutil.copy2(key, mount / f"{identity}.key.pem")
        os.chmod(mount / f"{identity}.key.pem", stat.S_IRUSR)

    for mount in (router_mount, client_mount):
        shutil.copy2(ca_cert, mount / "ca.pem")
    return router_mount, client_mount, inventory, "".join(log)


def docker_json(runner: CommandRunner, argv: list[str]) -> Any:
    """Run a Docker JSON command and decode its output."""
    output = runner.run(["docker", *argv]).stdout
    return json.loads(output)


def wait_for_router(runner: CommandRunner, container: str) -> None:
    """Wait briefly for the router process to remain running before the probe."""
    for _ in range(20):
        state = runner.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container],
            check=False,
        )
        if state.returncode == 0 and state.stdout.strip() == "true":
            time.sleep(1.0)
            confirm = runner.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container],
                check=False,
            )
            if confirm.returncode == 0 and confirm.stdout.strip() == "true":
                return
        time.sleep(0.25)
    logs = runner.run(["docker", "logs", container], check=False)
    raise CampaignError(f"router did not stay running: {logs.stderr[-4000:]}")


def remove_private_material(work: Path) -> bool:
    """Delete every raw/mounted private-key directory."""
    ok = True
    for name in ("pki-authority", "router-secrets", "client-secrets"):
        path = work / name
        try:
            if path.exists():
                shutil.rmtree(path)
        except OSError:
            ok = False
    return ok


def cleanup_runtime(
    runner: CommandRunner,
    router_container: str,
    probe_container: str,
    network: str,
    probe_image: str,
) -> dict[str, bool]:
    """Remove every mutable Docker object created by the campaign."""
    outcomes: dict[str, bool] = {}
    for label, argv in (
        ("probe_container_removed", ["docker", "rm", "--force", probe_container]),
        ("router_container_removed", ["docker", "rm", "--force", router_container]),
        ("network_removed", ["docker", "network", "rm", network]),
        ("probe_image_removed", ["docker", "image", "rm", "--force", probe_image]),
    ):
        try:
            process = runner.run(argv, check=False, timeout_seconds=30)
            outcomes[label] = process.returncode == 0
        except BaseException:
            # Cleanup actions are independent. A stuck Docker object must not
            # prevent later object removal or private-key deletion.
            outcomes[label] = False
    return outcomes


def write_checksums(evidence: Path) -> None:
    """Cover every retained evidence file except the checksum list itself."""
    lines = []
    for path in sorted(item for item in evidence.rglob("*") if item.is_file()):
        relative = path.relative_to(evidence).as_posix()
        if relative == "checksums.sha256":
            continue
        lines.append(f"{sha256_bytes(path.read_bytes())}  {relative}")
    (evidence / "checksums.sha256").write_text("\n".join(lines) + "\n")


def scan_candidate(evidence: Path) -> None:
    """Refuse to emit a candidate containing private keys or host paths."""
    for path in evidence.rglob("*"):
        if path.is_symlink():
            raise CampaignError("candidate evidence contains a symbolic link")
        if not path.is_file():
            continue
        if path.name.endswith(".key") or ".key." in path.name:
            raise CampaignError("candidate evidence contains a private-key filename")
        data = path.read_bytes()
        if PRIVATE_KEY_MARKER.search(data):
            raise CampaignError("candidate evidence contains private-key PEM material")
        if str(ROOT).encode() in data or str(evidence.parent).encode() in data:
            raise CampaignError("candidate evidence contains an unsanitized host path")


def build_evidence(
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
    commands: list[dict[str, Any]],
    pki_inventory: dict[str, Any],
    pki_log: str,
    docker_metadata: dict[str, Any],
) -> Path:
    """Build the sanitized candidate directory after successful cleanup."""
    evidence = work / "evidence"
    evidence.mkdir()
    configs = evidence / "configs"
    shutil.copytree(work / "rendered", configs)
    fixtures = evidence / "fixtures"
    fixtures.mkdir()
    shutil.copy2(
        work / "campaign" / "no-certificate.json",
        fixtures / "no-certificate.json",
    )
    logs = evidence / "logs"
    logs.mkdir()
    for source_name, retained_name in (
        ("probe.stdout.log", "probe.stdout.log"),
        ("probe.stderr.log", "probe.stderr.log"),
        ("router.log", "router.log"),
    ):
        source = work / "raw" / source_name
        (logs / retained_name).write_text(sanitize_text(source.read_text(), work))
    (logs / "pki-verification.log").write_text(sanitize_text(pki_log, work))
    (logs / "docker-metadata.json").write_bytes(
        canonical_json(sanitize_value(docker_metadata, work))
    )
    (evidence / "commands.json").write_bytes(canonical_json(commands))
    (evidence / "pki.json").write_bytes(canonical_json(pki_inventory))

    result_bytes = (work / "raw" / "result.json").read_bytes()
    result = json.loads(result_bytes)
    if result.get("status") != "pass":
        raise CampaignError("probe result is not a passing campaign")
    (evidence / "result.json").write_bytes(canonical_json(result))

    manifest = {
        "builder_image": BUILDER_IMAGE,
        "cleanup": {**cleanup, "private_material_removed": private_cleanup},
        "finished_at_utc": finished_at,
        "limitations": [
            "stock Zenoh 1.9 combines WebPKI roots with the configured custom CA",
            "the synthetic harness holds all ephemeral client keys in one test container",
            "local put return values are not used as delivery evidence",
            "this does not prove Gate service wiring, credential custody, Crebain application, or complete mediation",
        ],
        "profile_id": profile["profile_id"],
        "profile_sha256": sha256_bytes(profile_bytes),
        "result_sha256": sha256_bytes(canonical_json(result)),
        "router_image": profile["router"]["image"],
        "schema_version": 1,
        "source_commit": source_commit,
        "source_dirty": False,
        "source_snapshot_sha256": source_snapshot_sha256,
        "started_at_utc": started_at,
    }
    if manifest["router_image"] != EXPECTED_ROUTER_IMAGE:
        raise CampaignError("router image changed during campaign")
    (evidence / "manifest.json").write_bytes(canonical_json(manifest))
    (evidence / "README.md").write_text(
        "# Receiver-observed secure Zenoh ACL campaign\n\n"
        f"This candidate was generated from clean Haldir commit `{source_commit}` using "
        "the exact `haldir-secure-reference-v1` profile. Separate remote Zenoh sessions "
        "observed the fixed final-command/controller-intent ACL subset and a late "
        "quarantine window. Only callbacks count as delivery evidence; local `put()` "
        "returns and router logs are non-authoritative corroboration.\n\n"
        "The result is narrow: it exercises certificate-principal ACL behavior in the "
        "pinned synthetic deployment. It does not prove exclusive custom-CA trust, "
        "runtime Gate selection, credential custody, Crebain application, or complete "
        "mediation.\n"
    )
    write_checksums(evidence)
    scan_candidate(evidence)
    return evidence


def run_campaign(output: Path) -> Path:
    """Execute the current-profile campaign and return its candidate evidence path."""
    require_tools()
    work = require_safe_output(output)
    work.mkdir(parents=True)
    runner = CommandRunner(work)
    started_at = utc_now()
    source_commit = require_clean_source(runner)
    source_root, source_snapshot_sha256 = export_source_snapshot(
        runner, source_commit, work
    )
    source_profile_path = source_root / "deploy" / "secure-reference-v1" / "profile.json"
    profile_bytes = source_profile_path.read_bytes()
    profile = load_profile(source_profile_path)
    if profile["router"]["image"] != EXPECTED_ROUTER_IMAGE:
        raise CampaignError("source profile no longer uses the reviewed router image")
    rendered_files = render_bundle(profile)
    verify_bundle(profile, rendered_files)
    rendered = work / "rendered"
    write_bundle(rendered, rendered_files)
    campaign_input = work / "campaign"
    write_no_certificate_config(rendered, campaign_input)
    raw = work / "raw"
    raw.mkdir()

    suffix = secrets.token_hex(6)
    network = f"haldir-live-{suffix}"
    router_container = f"haldir-router-{suffix}"
    probe_container = f"haldir-probe-{suffix}"
    probe_image = f"haldir-live-secure-acl-probe:{suffix}"
    cleanup: dict[str, bool] = {}
    private_cleanup = False
    error: BaseException | None = None
    docker_metadata: dict[str, Any] = {}
    pki_inventory: dict[str, Any] = {}
    pki_log = ""

    try:
        # Build from the immutable git archive before any private key exists.
        runner.run(["docker", "pull", BUILDER_IMAGE], timeout_seconds=300)
        runner.run(["docker", "pull", EXPECTED_ROUTER_IMAGE], timeout_seconds=300)
        source_dockerfile = source_root / "tools" / "live-secure-zenoh" / "Dockerfile"
        runner.run(
            [
                "docker",
                "build",
                "--pull",
                "--file",
                str(source_dockerfile),
                "--tag",
                probe_image,
                str(source_root),
            ],
            timeout_seconds=1200,
        )
        router_mount, client_mount, pki_inventory, pki_log = generate_pki(
            runner, profile, work
        )
        (raw / "pki.json").write_bytes(canonical_json(pki_inventory))
        runner.run(
            ["docker", "network", "create", "--internal", network],
            timeout_seconds=60,
        )
        launch = json.loads((rendered / "router-launch.json").read_text())
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
                "RUST_LOG=zenoh::net::routing::interceptor::access_control=trace,zenoh_link_tls=debug,zenohd=info",
                EXPECTED_ROUTER_IMAGE,
                *router_argv,
            ],
            timeout_seconds=60,
        )
        wait_for_router(runner, router_container)
        probe = runner.run(
            [
                "docker",
                "run",
                "--name",
                probe_container,
                "--network",
                network,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
                "--mount",
                f"type=bind,src={client_mount},dst={RUNTIME_SECRET_ROOT},readonly",
                "--mount",
                f"type=bind,src={campaign_input},dst=/campaign,readonly",
                "--mount",
                f"type=bind,src={raw},dst=/evidence",
                "--env",
                "HALDIR_LIVE_ACL_CONFIG_DIR=/campaign",
                "--env",
                "HALDIR_LIVE_ACL_RESULT_PATH=/evidence/result.json",
                probe_image,
            ],
            check=False,
            timeout_seconds=240,
        )
        (raw / "probe.stdout.log").write_text(probe.stdout)
        (raw / "probe.stderr.log").write_text(probe.stderr)
        router_logs = runner.run(
            ["docker", "logs", router_container], check=False, timeout_seconds=60
        )
        (raw / "router.log").write_text(router_logs.stdout + router_logs.stderr)
        docker_metadata = {
            "builder_image": docker_json(runner, ["image", "inspect", BUILDER_IMAGE]),
            "docker_version": docker_json(runner, ["version", "--format", "{{json .}}"]),
            "probe_image": docker_json(runner, ["image", "inspect", probe_image]),
            "probe_container": docker_json(
                runner, ["container", "inspect", probe_container]
            ),
            "router_container": docker_json(runner, ["container", "inspect", router_container]),
            "router_image": docker_json(runner, ["image", "inspect", EXPECTED_ROUTER_IMAGE]),
        }
        if probe.returncode != 0:
            raise CampaignError(f"live probe failed with exit code {probe.returncode}")
        if not (raw / "result.json").is_file():
            raise CampaignError("live probe emitted no machine-readable result")
        if require_clean_source(runner) != source_commit:
            raise CampaignError("source HEAD changed while the immutable snapshot campaign ran")
    except BaseException as caught:  # cleanup must run even for interruption
        error = caught
    finally:
        try:
            cleanup = cleanup_runtime(
                runner, router_container, probe_container, network, probe_image
            )
        finally:
            private_cleanup = remove_private_material(work)
        (raw / "commands.json").write_bytes(canonical_json(runner.commands))

    if error is not None:
        if isinstance(error, Exception):
            raise CampaignError(f"campaign failed after cleanup: {error}") from error
        raise error
    if not all(cleanup.values()) or not private_cleanup:
        raise CampaignError("campaign passed but disposable runtime cleanup was incomplete")
    finished_at = utc_now()
    return build_evidence(
        work=work,
        source_commit=source_commit,
        source_snapshot_sha256=source_snapshot_sha256,
        profile=profile,
        profile_bytes=profile_bytes,
        started_at=started_at,
        finished_at=finished_at,
        cleanup=cleanup,
        private_cleanup=private_cleanup,
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
        evidence = run_campaign(args.output)
    except (CampaignError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"run-live-secure-zenoh: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"run-live-secure-zenoh: OK (candidate evidence: {evidence})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
