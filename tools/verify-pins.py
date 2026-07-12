#!/usr/bin/env python3
"""Reject floating or ambiguous source pins.

Enforces:
  * the NCP commit is a full 40-hex SHA (never a branch name or short SHA);
  * the Rust toolchain channel is an exact release (never "stable"/"nightly");
  * rust-toolchain.toml agrees with tools/pins.toml;
  * the compiled NCP compatibility constants agree with tools/pins.toml;
  * Cargo.lock exists (dependencies are pinned).

Exits non-zero on the first violation. No third-party dependencies.
"""
from __future__ import annotations

import hashlib
import re
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

    if not (ROOT / "Cargo.lock").is_file():
        fail("Cargo.lock missing (dependencies must be pinned)")
    cargo_lock = (ROOT / "Cargo.lock").read_text()
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
    fields = {
        "ncp_tag": "tag",
        "ncp_commit": "commit",
        "wire_version": "wire_version",
        "contract_hash": "contract_hash",
        "proto_sha256": "proto_sha256",
        "capability_profile": "capability_profile",
    }
    for rust_field, pin_field in fields.items():
        expected = pins.get("ncp", {}).get(pin_field, "")
        if f'{rust_field}: "{expected}"' not in compatibility:
            fail(
                f"haldir-ncp08 {rust_field} disagrees with "
                f"tools/pins.toml ncp.{pin_field}"
            )

    print(
        "verify-pins: OK "
        "(NCP record/dependency/corpus, toolchain channel, proto digest, Cargo.lock)"
    )


if __name__ == "__main__":
    main()
