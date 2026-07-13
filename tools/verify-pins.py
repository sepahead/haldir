#!/usr/bin/env python3
"""Reject floating or ambiguous source pins.

Enforces:
  * the NCP commit is a full 40-hex SHA (never a branch name or short SHA);
  * the Rust toolchain channel is an exact release (never "stable"/"nightly");
  * rust-toolchain.toml agrees with tools/pins.toml;
  * the compiled NCP compatibility constants agree with tools/pins.toml;
  * the always-on NCP key builder and off-by-default Zenoh transport use exact pins;
  * Zenoh has default features off and TLS as its sole enabled transport feature;
  * Cargo.lock exists (dependencies are pinned).

Exits non-zero on the first violation. No third-party dependencies.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(msg: str) -> None:
    print(f"verify-pins: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    pins_path = ROOT / "tools" / "pins.toml"
    if not pins_path.is_file():
        fail("tools/pins.toml missing")
    pins = tomllib.loads(pins_path.read_text())

    commit = pins.get("ncp", {}).get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail(f"ncp.commit is not a full 40-hex SHA: {commit!r}")

    channel = pins.get("toolchain", {}).get("rust_channel", "")
    if channel in {"stable", "nightly", "", "beta"}:
        fail(f"toolchain.rust_channel must be exact, got {channel!r}")
    if not re.fullmatch(r"\d+\.\d+(\.\d+)?", channel):
        fail(f"toolchain.rust_channel must look like a release, got {channel!r}")

    rt_path = ROOT / "rust-toolchain.toml"
    if not rt_path.is_file():
        fail("rust-toolchain.toml missing")
    rt = tomllib.loads(rt_path.read_text())
    rt_channel = rt.get("toolchain", {}).get("channel", "")
    if rt_channel != channel:
        fail(f"rust-toolchain.toml channel {rt_channel!r} != pins {channel!r}")

    lock_path = ROOT / "Cargo.lock"
    if not lock_path.is_file():
        fail("Cargo.lock missing (dependencies must be pinned)")
    cargo_lock = lock_path.read_text()
    cargo_lock_data = tomllib.loads(cargo_lock)
    ncp_source = f"git+https://github.com/sepahead/NCP?rev={commit}#{commit}"
    if f'source = "{ncp_source}"' not in cargo_lock:
        fail("Cargo.lock does not resolve ncp-core from the exact pinned NCP revision")

    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
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
    zenoh_dep = workspace_deps.get("zenoh", {})
    if (
        zenoh_dep.get("version") != f"={zenoh_version}"
        or zenoh_dep.get("default-features") is not False
        or zenoh_dep.get("features") != expected_zenoh_features
    ):
        fail("workspace zenoh dependency is not exact, TLS-only, and default-features=false")
    tokio_dep = workspace_deps.get("tokio", {})
    if (
        tokio_dep.get("default-features") is not False
        or tokio_dep.get("features") != ["sync"]
    ):
        fail("workspace Tokio dependency must be default-features=false with only sync")

    zenoh_packages = [
        package
        for package in cargo_lock_data.get("package", [])
        if package.get("name") == "zenoh"
    ]
    if len(zenoh_packages) != 1 or zenoh_packages[0].get("version") != zenoh_version:
        fail(f"Cargo.lock must resolve exactly zenoh {zenoh_version}")
    if zenoh_packages[0].get("source") != "registry+https://github.com/rust-lang/crates.io-index":
        fail("Cargo.lock zenoh package is not from the admitted crates.io registry")

    transport_manifest = tomllib.loads(
        (ROOT / "crates" / "haldir-transport-zenoh" / "Cargo.toml").read_text()
    )
    transport_features = transport_manifest.get("features", {})
    if transport_features.get("default") != []:
        fail("haldir-transport-zenoh default features must remain empty")
    if transport_features.get("live-zenoh") != [
        "dep:haldir-ncp08",
        "haldir-ncp08/real-ncp",
        "dep:serde_json",
        "dep:tokio",
        "dep:zenoh",
    ]:
        fail("haldir-transport-zenoh live-zenoh feature dependency set changed")
    transport_deps = transport_manifest.get("dependencies", {})
    if transport_deps.get("ncp-core", {}).get("workspace") is not True:
        fail("haldir-transport-zenoh must always use workspace-pinned ncp-core")
    if transport_deps.get("ncp-core", {}).get("optional") is True:
        fail("haldir-transport-zenoh ncp-core key builder must not be optional")
    if transport_deps.get("zenoh") != {"workspace": True, "optional": True}:
        fail("haldir-transport-zenoh Zenoh dependency must remain workspace-pinned and optional")
    if "ncp-zenoh" in transport_deps:
        fail("haldir-transport-zenoh must not import the broader ncp-zenoh feature graph")

    try:
        metadata_process = subprocess.run(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--all-features",
                "--locked",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        metadata = json.loads(metadata_process.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        fail(f"cannot inspect the locked all-feature Cargo graph: {error}")
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
    profile = json.loads(
        (ROOT / "deploy" / "secure-reference-v1" / "profile.json").read_text()
    )
    if profile.get("router", {}).get("image") != router_image:
        fail("live transport router pin differs from the secure-reference profile")
    dockerfile = (
        ROOT / "tools" / "live-secure-zenoh" / "Dockerfile"
    ).read_text()
    from_images = re.findall(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    if from_images != [probe_builder_image, probe_builder_image]:
        fail("every live probe Dockerfile stage must use the pinned builder image")
    if dockerfile.lstrip().startswith("# syntax="):
        fail("live probe Dockerfile must not select a mutable frontend tag")
    dockerignore = (
        ROOT / "tools" / "live-secure-zenoh" / "Dockerfile.dockerignore"
    ).read_text()
    if not dockerignore.startswith("**\n") or "!target" in dockerignore:
        fail("live probe Docker context must default-deny and exclude target")
    runner_source = (ROOT / "tools" / "live_secure_zenoh.py").read_text()
    for image in (probe_builder_image, router_image):
        digest = image.rsplit("@", maxsplit=1)[1]
        if runner_source.count(digest) != 1:
            fail("live campaign runner image constants differ from tools/pins.toml")

    descriptor = (ROOT / ".ncp-consumer").read_text()
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
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = pins.get("ncp", {}).get(pin_field, "")
        if actual != expected:
            fail(f"frozen NCP corpus digest mismatch for {filename}: {actual}")

    compatibility_path = ROOT / "crates" / "haldir-ncp08" / "src" / "compatibility.rs"
    compatibility = compatibility_path.read_text()
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
        "toolchain, Cargo.lock)"
    )


if __name__ == "__main__":
    main()
