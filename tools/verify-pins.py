#!/usr/bin/env python3
"""Reject floating or ambiguous source pins.

Enforces:
  * the NCP commit is a full 40-hex SHA (never a branch name or short SHA);
  * the Rust toolchain channel is an exact release (never "stable"/"nightly");
  * rust-toolchain.toml agrees with tools/pins.toml;
  * Cargo.lock exists (dependencies are pinned).

Exits non-zero on the first violation. No third-party dependencies.
"""
from __future__ import annotations

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

    proto_sha = pins.get("ncp", {}).get("proto_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", proto_sha):
        fail(f"ncp.proto_sha256 is not a 64-hex digest: {proto_sha!r}")

    print("verify-pins: OK (ncp commit, toolchain channel, proto digest, Cargo.lock)")


if __name__ == "__main__":
    main()
