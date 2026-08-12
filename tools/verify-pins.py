#!/usr/bin/env python3
"""Reject floating or ambiguous source pins.

Enforces:
  * the NCP commit is a full 40-hex SHA (never a branch name or short SHA);
  * the Rust toolchain channel is an exact release (never "stable"/"nightly");
  * rust-toolchain.toml agrees with tools/pins.toml;
  * the compiled NCP compatibility constants agree with tools/pins.toml;
  * the always-on NCP key builder and off-by-default Zenoh transport use exact pins;
  * Zenoh has default features off and TLS as its sole enabled transport feature;
  * Cargo.lock exists (dependencies are pinned);
  * protected workflows cannot execute the retired cargo-deny Action;
  * cargo-deny binaries and the RustSec snapshot have exact bounded identities.
  * the formal model-checker jar and Java runtime have exact closed pins.

Exits non-zero on the first violation. No third-party dependencies.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_TEST_TIMEOUT_SECONDS = 60
MAX_SMALL_FILE_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_LOCK_BYTES = 8 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_METADATA_ERROR_BYTES = 64 * 1024
METADATA_TIMEOUT_SECONDS = 120.0


def fail(msg: str) -> None:
    print(f"verify-pins: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _read_regular_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    """Read one stable, bounded, no-follow regular repository file."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    before = None
    if nofollow:
        flags |= nofollow
    else:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            fail(f"{label} must be a regular file")
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            fail(f"{label} must be a regular file")
        if before is not None and (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            fail(f"{label} changed while it was opened")
        if not 1 <= opened.st_size <= maximum:
            fail(f"{label} violates its {maximum}-byte bound")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            try:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) > maximum:
            fail(f"{label} violates its {maximum}-byte bound")
        if (
            (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            or opened.st_size != after.st_size
            or opened.st_mtime_ns != after.st_mtime_ns
            or len(payload) != after.st_size
        ):
            fail(f"{label} changed while it was read")
        if b"\0" in payload:
            fail(f"{label} contains a NUL byte")
        return payload
    finally:
        os.close(descriptor)


def _read_regular_text(path: Path, *, maximum: int, label: str) -> str:
    payload = _read_regular_bytes(path, maximum=maximum, label=label)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} is not valid UTF-8: {error}")


def _cargo_executable() -> str:
    """Resolve Cargo explicitly, preferring the gate-validated toolchain path."""

    supplied = os.environ.get("HALDIR_CARGO")
    candidate = supplied if supplied is not None else shutil.which("cargo")
    if candidate is None:
        fail("cargo executable not found")
    path = Path(candidate)
    if not path.is_absolute():
        fail("cargo executable must resolve to an absolute path")
    try:
        metadata = path.stat()
    except OSError as error:
        fail(f"cannot inspect cargo executable: {error}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & stat.S_IXUSR == 0
        or metadata.st_mode & 0o022 != 0
    ):
        fail("cargo executable must be owner-executable and not group/world-writable")
    return str(path)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _cargo_metadata() -> dict[str, object]:
    """Return locked all-feature metadata with hard time and byte bounds."""

    command = (
        _cargo_executable(),
        "metadata",
        "--format-version",
        "1",
        "--all-features",
        "--locked",
    )
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        fail(f"cannot inspect the locked all-feature Cargo graph: {error}")
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        fail("cannot inspect the locked all-feature Cargo graph: missing pipe")

    streams = {
        process.stdout: (bytearray(), MAX_METADATA_BYTES, "stdout"),
        process.stderr: (bytearray(), MAX_METADATA_ERROR_BYTES, "stderr"),
    }
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + METADATA_TIMEOUT_SECONDS
    failure: str | None = None
    try:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timed out"
                break
            events = selector.select(remaining)
            if not events:
                continue
            for key, _mask in events:
                stream = key.fileobj
                buffer, maximum, label = streams[stream]
                allowance = maximum + 1 - len(buffer)
                try:
                    chunk = os.read(stream.fileno(), min(64 * 1024, allowance))
                except InterruptedError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > maximum:
                    failure = f"{label} exceeds its byte bound"
                    break
            if failure is not None:
                break
        if failure is None:
            try:
                returncode = process.wait(max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failure = "timed out"
                returncode = -1
        else:
            returncode = -1
    except OSError as error:
        failure = str(error)
        returncode = -1
    except BaseException:
        _stop_process(process)
        raise
    finally:
        selector.close()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass

    stdout = bytes(streams[process.stdout][0])
    stderr = bytes(streams[process.stderr][0])
    if failure is not None or returncode != 0:
        _stop_process(process)
        detail = stderr.decode("utf-8", errors="replace").strip()[:500]
        fail(
            "cannot inspect the locked all-feature Cargo graph: "
            + (failure or detail or f"exit {returncode}")
        )
    try:
        value = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode the locked all-feature Cargo graph: {error}")
    if type(value) is not dict:
        fail("locked all-feature Cargo metadata root is not an object")
    return value


def verify_cargo_deny_policy(pins: dict[str, object]) -> None:
    """Load the sibling policy module by exact path and enforce it in CI."""

    module_path = ROOT / "tools" / "pinned_cargo_deny.py"
    if not module_path.is_file() or module_path.is_symlink():
        fail("tools/pinned_cargo_deny.py must be a regular file")
    try:
        namespace = runpy.run_path(str(module_path))
        verifier = namespace["verify_repository_policy"]
        policy_error = namespace["PinPolicyError"]
        verifier(ROOT, pins)
    except KeyError as error:
        fail(f"cargo-deny pin verifier API is missing: {error}")
    except (OSError, SyntaxError, TypeError) as error:
        fail(f"cannot load cargo-deny pin verifier: {error}")
    except policy_error as error:
        fail(str(error))


def verify_cargo_deny_tests() -> None:
    """Run the adversarial archive/installer suite on every authoritative gate."""

    test_path = ROOT / "tools" / "test_pinned_cargo_deny.py"
    if not test_path.is_file() or test_path.is_symlink():
        fail("tools/test_pinned_cargo_deny.py must be a regular file")
    try:
        completed = subprocess.run(
            (sys.executable, "-I", "-B", str(test_path)),
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            check=False,
            timeout=PIN_TEST_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"cannot run cargo-deny pin tests: {error}")
    if completed.returncode != 0:
        fail(f"cargo-deny pin tests failed with status {completed.returncode}")


def main() -> None:
    pins_path = ROOT / "tools" / "pins.toml"
    try:
        pins = tomllib.loads(
            _read_regular_text(
                pins_path,
                maximum=MAX_SMALL_FILE_BYTES,
                label="tools/pins.toml",
            )
        )
    except tomllib.TOMLDecodeError as error:
        fail(f"tools/pins.toml is invalid TOML: {error}")
    verify_cargo_deny_policy(pins)
    verify_cargo_deny_tests()

    commit = pins.get("ncp", {}).get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail(f"ncp.commit is not a full 40-hex SHA: {commit!r}")

    channel = pins.get("toolchain", {}).get("rust_channel", "")
    if channel in {"stable", "nightly", "", "beta"}:
        fail(f"toolchain.rust_channel must be exact, got {channel!r}")
    if not re.fullmatch(r"\d+\.\d+(\.\d+)?", channel):
        fail(f"toolchain.rust_channel must look like a release, got {channel!r}")

    rt_path = ROOT / "rust-toolchain.toml"
    try:
        rt = tomllib.loads(
            _read_regular_text(
                rt_path,
                maximum=MAX_SMALL_FILE_BYTES,
                label="rust-toolchain.toml",
            )
        )
    except tomllib.TOMLDecodeError as error:
        fail(f"rust-toolchain.toml is invalid TOML: {error}")
    rt_channel = rt.get("toolchain", {}).get("channel", "")
    if rt_channel != channel:
        fail(f"rust-toolchain.toml channel {rt_channel!r} != pins {channel!r}")

    lock_path = ROOT / "Cargo.lock"
    cargo_lock = _read_regular_text(
        lock_path,
        maximum=MAX_LOCK_BYTES,
        label="Cargo.lock",
    )
    try:
        cargo_lock_data = tomllib.loads(cargo_lock)
    except tomllib.TOMLDecodeError as error:
        fail(f"Cargo.lock is invalid TOML: {error}")
    ncp_source = f"git+https://github.com/sepahead/NCP?rev={commit}#{commit}"
    if f'source = "{ncp_source}"' not in cargo_lock:
        fail("Cargo.lock does not resolve ncp-core from the exact pinned NCP revision")

    try:
        cargo = tomllib.loads(
            _read_regular_text(
                ROOT / "Cargo.toml",
                maximum=MAX_MANIFEST_BYTES,
                label="Cargo.toml",
            )
        )
    except tomllib.TOMLDecodeError as error:
        fail(f"Cargo.toml is invalid TOML: {error}")
    ncp_dep = cargo.get("workspace", {}).get("dependencies", {}).get("ncp-core", {})
    if (
        ncp_dep.get("git") != "https://github.com/sepahead/NCP"
        or ncp_dep.get("rev") != commit
        or ncp_dep.get("version") != "=0.8.0"
    ):
        fail("workspace ncp-core dependency is not exact v0.8.0 at ncp.commit")

    zenoh_pin = pins.get("zenoh", {})
    zenoh_version = zenoh_pin.get("version", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", zenoh_version):
        fail(f"zenoh.version must be an exact release, got {zenoh_version!r}")
    expected_zenoh_features = ["transport_tls"]
    if zenoh_pin.get("default_features") is not False:
        fail("zenoh.default_features must be false")
    if zenoh_pin.get("features") != expected_zenoh_features:
        fail("zenoh.features must contain only transport_tls")

    workspace_deps = cargo.get("workspace", {}).get("dependencies", {})
    dependency_pins = pins.get("dependencies", {})
    ed25519_pin = dependency_pins.get("ed25519-compact", "")
    ed25519_dep = workspace_deps.get("ed25519-compact", {})
    if ed25519_pin != "2.3.1" or ed25519_dep != {
        "version": f"={ed25519_pin}",
        "default-features": False,
        "features": ["std"],
    }:
        fail("workspace ed25519-compact dependency differs from its exact reviewed pin")
    curve25519_pin = dependency_pins.get("curve25519-dalek", "")
    curve25519_dep = workspace_deps.get("curve25519-dalek", {})
    if curve25519_pin != "4.1.3" or curve25519_dep != {
        "version": f"={curve25519_pin}",
        "default-features": False,
    }:
        fail("workspace curve25519-dalek dependency differs from its exact reviewed pin")
    rustix_pin = pins.get("dependencies", {}).get("rustix", "")
    rustix_dep = workspace_deps.get("rustix", {})
    if rustix_pin != "1.1.4" or rustix_dep != {
        "version": f"={rustix_pin}",
        "default-features": False,
        "features": ["std", "fs"],
    }:
        fail("workspace rustix dependency differs from its exact direct pin")
    zenoh_dep = workspace_deps.get("zenoh", {})
    if (
        zenoh_dep.get("version") != f"={zenoh_version}"
        or zenoh_dep.get("default-features") is not False
        or zenoh_dep.get("features") != expected_zenoh_features
    ):
        fail(
            "workspace zenoh dependency is not exact, TLS-only, and default-features=false"
        )
    tokio_dep = workspace_deps.get("tokio", {})
    if tokio_dep.get("default-features") is not False or tokio_dep.get("features") != [
        "sync"
    ]:
        fail("workspace Tokio dependency must be default-features=false with only sync")

    zenoh_packages = [
        package
        for package in cargo_lock_data.get("package", [])
        if package.get("name") == "zenoh"
    ]
    if len(zenoh_packages) != 1 or zenoh_packages[0].get("version") != zenoh_version:
        fail(f"Cargo.lock must resolve exactly zenoh {zenoh_version}")
    if (
        zenoh_packages[0].get("source")
        != "registry+https://github.com/rust-lang/crates.io-index"
    ):
        fail("Cargo.lock zenoh package is not from the admitted crates.io registry")
    backport_repository = "https://github.com/sepahead/zenoh-transport-lz4-backport"
    backport_commit = "6b93b15d0795748b7f76c72eae07f1cda517e762"
    backport_pin = f"1.9.0@{backport_commit}"
    if dependency_pins.get("zenoh-transport") != backport_pin:
        fail("dependencies.zenoh-transport differs from the reviewed backport")
    cargo_patch = cargo.get("patch", {}).get("crates-io", {}).get("zenoh-transport", {})
    if cargo_patch != {"git": backport_repository, "rev": backport_commit}:
        fail("Cargo.toml zenoh-transport backport is not the exact reviewed revision")
    backport_packages = [
        package
        for package in cargo_lock_data.get("package", [])
        if package.get("name") == "zenoh-transport"
    ]
    expected_backport_source = (
        f"git+{backport_repository}?rev={backport_commit}#{backport_commit}"
    )
    if len(backport_packages) != 1 or backport_packages[0].get("version") != "1.9.0":
        fail("Cargo.lock must resolve exactly one zenoh-transport 1.9.0 package")
    if backport_packages[0].get("source") != expected_backport_source:
        fail("Cargo.lock zenoh-transport does not resolve the reviewed Git object")
    lz4_packages = [
        package
        for package in cargo_lock_data.get("package", [])
        if package.get("name") == "lz4_flex"
    ]
    if len(lz4_packages) != 1 or lz4_packages[0].get("version") != "0.11.6":
        fail("Cargo.lock must resolve only the fixed lz4_flex 0.11.6 package")
    rustix_packages = [
        package
        for package in cargo_lock_data.get("package", [])
        if package.get("name") == "rustix"
    ]
    if len(rustix_packages) != 1 or rustix_packages[0].get("version") != rustix_pin:
        fail(f"Cargo.lock must resolve exactly rustix {rustix_pin}")
    if (
        rustix_packages[0].get("source")
        != "registry+https://github.com/rust-lang/crates.io-index"
    ):
        fail("Cargo.lock rustix package is not from the admitted crates.io registry")
    ed25519_packages = [
        package
        for package in cargo_lock_data.get("package", [])
        if package.get("name") == "ed25519-compact"
    ]
    if len(ed25519_packages) != 1 or ed25519_packages[0].get("version") != ed25519_pin:
        fail(f"Cargo.lock must resolve exactly ed25519-compact {ed25519_pin}")
    if (
        ed25519_packages[0].get("source")
        != "registry+https://github.com/rust-lang/crates.io-index"
    ):
        fail("Cargo.lock ed25519-compact package is not from crates.io")
    curve25519_packages = [
        package
        for package in cargo_lock_data.get("package", [])
        if package.get("name") == "curve25519-dalek"
    ]
    if (
        len(curve25519_packages) != 1
        or curve25519_packages[0].get("version") != curve25519_pin
    ):
        fail(f"Cargo.lock must resolve exactly curve25519-dalek {curve25519_pin}")
    if (
        curve25519_packages[0].get("source")
        != "registry+https://github.com/rust-lang/crates.io-index"
    ):
        fail("Cargo.lock curve25519-dalek package is not from crates.io")
    subtle_pin = dependency_pins.get("subtle", "")
    subtle_packages = [
        package
        for package in cargo_lock_data.get("package", [])
        if package.get("name") == "subtle"
    ]
    if subtle_pin != "2.6.1" or len(subtle_packages) != 1 or subtle_packages[0].get(
        "version"
    ) != subtle_pin:
        fail(f"Cargo.lock must resolve exactly subtle {subtle_pin}")
    if (
        subtle_packages[0].get("source")
        != "registry+https://github.com/rust-lang/crates.io-index"
    ):
        fail("Cargo.lock subtle package is not from crates.io")

    transport_manifest_path = ROOT / "crates" / "haldir-transport-zenoh" / "Cargo.toml"
    try:
        transport_manifest = tomllib.loads(
            _read_regular_text(
                transport_manifest_path,
                maximum=MAX_MANIFEST_BYTES,
                label="crates/haldir-transport-zenoh/Cargo.toml",
            )
        )
    except tomllib.TOMLDecodeError as error:
        fail(f"haldir-transport-zenoh Cargo.toml is invalid TOML: {error}")
    transport_features = transport_manifest.get("features", {})
    if transport_features.get("default") != []:
        fail("haldir-transport-zenoh default features must remain empty")
    if transport_features.get("live-zenoh") != [
        "dep:haldir-contracts",
        "dep:haldir-ncp08",
        "haldir-ncp08/real-ncp",
        "dep:serde_json",
        "dep:rustix",
        "dep:tokio",
        "dep:zenoh",
    ]:
        fail("haldir-transport-zenoh live-zenoh feature dependency set changed")
    transport_deps = transport_manifest.get("dependencies", {})
    if transport_deps.get("ncp-core", {}).get("workspace") is not True:
        fail("haldir-transport-zenoh must always use workspace-pinned ncp-core")
    if transport_deps.get("ncp-core", {}).get("optional") is True:
        fail("haldir-transport-zenoh ncp-core key builder must not be optional")
    for dependency in (
        "haldir-contracts",
        "haldir-ncp08",
        "rustix",
        "serde_json",
        "tokio",
        "zenoh",
    ):
        if transport_deps.get(dependency) != {"workspace": True, "optional": True}:
            fail(
                "haldir-transport-zenoh "
                f"{dependency} dependency must remain workspace-pinned and optional"
            )
    if "ncp-zenoh" in transport_deps:
        fail(
            "haldir-transport-zenoh must not import the broader ncp-zenoh feature graph"
        )

    metadata = _cargo_metadata()
    packages = {package["id"]: package for package in metadata.get("packages", [])}
    zenoh_nodes = []
    for node in metadata.get("resolve", {}).get("nodes", []):
        package = packages.get(node.get("id"), {})
        if str(package.get("name", "")).startswith("zenoh"):
            zenoh_nodes.append((package, set(node.get("features", []))))
    root_zenoh = [
        features
        for package, features in zenoh_nodes
        if package.get("name") == "zenoh" and package.get("version") == zenoh_version
    ]
    if root_zenoh != [{"transport_tls"}]:
        fail(f"resolved Zenoh root features differ from TLS-only: {root_zenoh!r}")
    for package, features in zenoh_nodes:
        forbidden = {
            feature
            for feature in features
            if "compression" in feature
            or (feature.startswith("transport_") and feature != "transport_tls")
        }
        if forbidden:
            fail(
                f"resolved {package.get('name')} enables forbidden Zenoh features: "
                f"{sorted(forbidden)!r}"
            )

    live_transport = pins.get("live_transport", {})
    probe_builder_image = live_transport.get("probe_builder_image", "")
    router_image = live_transport.get("router_image", "")
    image_pin = re.compile(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}")
    if image_pin.fullmatch(probe_builder_image) is None:
        fail("live_transport.probe_builder_image must be an immutable digest")
    if image_pin.fullmatch(router_image) is None:
        fail("live_transport.router_image must be an immutable digest")
    try:
        profile = json.loads(
            _read_regular_text(
                ROOT / "deploy" / "secure-reference-v1" / "profile.json",
                maximum=MAX_MANIFEST_BYTES,
                label="deploy/secure-reference-v1/profile.json",
            )
        )
    except json.JSONDecodeError as error:
        fail(f"secure-reference profile is invalid JSON: {error}")
    if profile.get("router", {}).get("image") != router_image:
        fail("live transport router pin differs from the secure-reference profile")
    dockerfile = _read_regular_text(
        ROOT / "tools" / "live-secure-zenoh" / "Dockerfile",
        maximum=MAX_MANIFEST_BYTES,
        label="tools/live-secure-zenoh/Dockerfile",
    )
    from_images = re.findall(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    if from_images != [probe_builder_image, probe_builder_image]:
        fail("every live probe Dockerfile stage must use the pinned builder image")
    if dockerfile.lstrip().startswith("# syntax="):
        fail("live probe Dockerfile must not select a mutable frontend tag")
    dockerignore = _read_regular_text(
        ROOT / "tools" / "live-secure-zenoh" / "Dockerfile.dockerignore",
        maximum=MAX_SMALL_FILE_BYTES,
        label="tools/live-secure-zenoh/Dockerfile.dockerignore",
    )
    if not dockerignore.startswith("**\n") or "!target" in dockerignore:
        fail("live probe Docker context must default-deny and exclude target")
    runner_source = _read_regular_text(
        ROOT / "tools" / "live_secure_zenoh.py",
        maximum=MAX_SOURCE_BYTES,
        label="tools/live_secure_zenoh.py",
    )
    for image in (probe_builder_image, router_image):
        digest = image.rsplit("@", maxsplit=1)[1]
        if runner_source.count(digest) != 1:
            fail("live campaign runner image constants differ from tools/pins.toml")

    descriptor = _read_regular_text(
        ROOT / ".ncp-consumer",
        maximum=MAX_SMALL_FILE_BYTES,
        label=".ncp-consumer",
    )
    expected_descriptor_suffix = f"v0.8.0 {commit}"
    if descriptor.count(expected_descriptor_suffix) != 2:
        fail(".ncp-consumer does not contain exact manifest and lock revision rows")

    proto_sha = pins.get("ncp", {}).get("proto_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", proto_sha):
        fail(f"ncp.proto_sha256 is not a 64-hex digest: {proto_sha!r}")

    corpus_root = ROOT / "crates" / "haldir-ncp08" / "tests" / "data" / "ncp-v0.8.0"
    corpus = {
        "command_frame.json": "command_vector_sha256",
        "command_frame.schema.json": "command_schema_sha256",
    }
    for filename, pin_field in corpus.items():
        path = corpus_root / filename
        if not path.is_file():
            fail(f"frozen NCP corpus file missing: {path.relative_to(ROOT)}")
        actual = hashlib.sha256(
            _read_regular_bytes(
                path,
                maximum=MAX_SOURCE_BYTES,
                label=str(path.relative_to(ROOT)),
            )
        ).hexdigest()
        expected = pins.get("ncp", {}).get(pin_field, "")
        if actual != expected:
            fail(f"frozen NCP corpus digest mismatch for {filename}: {actual}")

    compatibility_path = ROOT / "crates" / "haldir-ncp08" / "src" / "compatibility.rs"
    compatibility = _read_regular_text(
        compatibility_path,
        maximum=MAX_SOURCE_BYTES,
        label="crates/haldir-ncp08/src/compatibility.rs",
    )
    baseline_match = re.search(
        r"pub const NCP_V0_8_0: NcpCompatibilityRecordV1 = "
        r"NcpCompatibilityRecordV1 \{\n(?P<body>.*?)\n\};",
        compatibility,
        flags=re.DOTALL,
    )
    if baseline_match is None:
        fail("haldir-ncp08 NCP_V0_8_0 baseline record is missing or malformed")
    baseline = baseline_match.group("body")
    fields = {
        "ncp_tag": "tag",
        "ncp_commit": "commit",
        "wire_version": "wire_version",
        "contract_hash": "contract_hash",
        "proto_sha256": "proto_sha256",
        "command_schema_sha256": "command_schema_sha256",
        "command_vector_sha256": "command_vector_sha256",
        "capability_profile": "capability_profile",
    }
    for rust_field, pin_field in fields.items():
        expected = pins.get("ncp", {}).get(pin_field, "")
        field_pattern = (
            rf'(?m)^\s*{re.escape(rust_field)}:\s*"{re.escape(str(expected))}",\s*$'
        )
        if re.search(field_pattern, baseline) is None:
            fail(
                f"haldir-ncp08 {rust_field} disagrees with "
                f"tools/pins.toml ncp.{pin_field}"
            )

    enabled_increment = pins.get("ncp", {}).get("enabled_increment")
    if type(enabled_increment) is not int or enabled_increment <= 0:
        fail("ncp.enabled_increment must be a positive integer")
    increment_pattern = rf"(?m)^\s*enabled_increment:\s*{enabled_increment},\s*$"
    if re.search(increment_pattern, baseline) is None:
        fail(
            "haldir-ncp08 enabled_increment disagrees with "
            "tools/pins.toml ncp.enabled_increment"
        )
    adapter_version_pattern = (
        r'(?m)^\s*haldir_adapter_version:\s*env!\("CARGO_PKG_VERSION"\),\s*$'
    )
    if re.search(adapter_version_pattern, baseline) is None:
        fail("haldir-ncp08 adapter version must come from the compiled package version")

    print(
        "verify-pins: OK "
        "(NCP command-subset record/dependency/corpus, exact TLS-only Zenoh, "
        "toolchain, Cargo.lock, closed cargo-deny/RustSec/formal identities)"
    )


if __name__ == "__main__":
    main()
