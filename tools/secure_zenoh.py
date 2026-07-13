#!/usr/bin/env python3
"""Deterministic secure-Zenoh deployment rendering and static verification.

This module uses only the Python standard library. It proves configuration shape
and exact ACL intent; it does not start Zenoh or provide live delivery evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "deploy" / "secure-reference-v1" / "profile.json"
IDENTITY_ROOT = "/run/secrets/haldir-secure-reference-v1"
ROUTER_CONFIG_PATH = "/etc/haldir-secure-reference-v1/router.json5"

PROFILE_KEYS = {
    "controllers",
    "principals",
    "profile_id",
    "realm",
    "router",
    "routes",
    "schema_version",
    "session_id",
    "zenoh_version",
}
PRINCIPAL_KEYS = {
    "certificate_common_name",
    "publish",
    "query",
    "role",
    "serve",
    "subscribe",
}
ROUTER_KEYS = {"certificate_common_name", "client_endpoint", "image", "listen_endpoint"}
ZENOH_IMAGE = (
    "docker.io/eclipse/zenoh@sha256:"
    "157965d71e0bfd0a044d76a985ff0e5c306ad3968929168fb9678cd2a7fec23f"
)
CONTROLLERS = ["controller-a", "controller-b"]
PRINCIPAL_ROLES = {
    "admission-authority": "admission-authority",
    "controller-a": "controller",
    "controller-b": "controller",
    "gate": "gate",
    "lifecycle": "lifecycle",
    "mission-authority": "mission-authority",
    "observer": "observer",
    "robot-crebain": "robot",
}
EXPECTED_CNS = {
    principal_id: f"haldir-{principal_id}.secure-reference-v1"
    for principal_id in PRINCIPAL_ROLES
}
EXPECTED_MATRIX = {
    "admission-authority": {
        "publish": ["admission_record", "admission_revocation"],
        "subscribe": ["gate_challenge", "gate_status"],
        "query": [],
        "serve": [],
    },
    "controller-a": {
        "publish": ["controller_a_intent"],
        "subscribe": ["state_pose", "gate_challenge", "gate_status"],
        "query": [],
        "serve": [],
    },
    "controller-b": {
        "publish": ["controller_b_intent"],
        "subscribe": ["state_pose", "gate_challenge", "gate_status"],
        "query": [],
        "serve": [],
    },
    "gate": {
        "publish": [
            "final_command",
            "gate_challenge",
            "decision_evidence",
            "gate_status",
        ],
        "subscribe": [
            "controller_a_intent",
            "controller_b_intent",
            "state_pose",
            "session_status",
            "mission_lease",
            "mission_revocation",
            "admission_record",
            "admission_revocation",
            "application_evidence",
        ],
        "query": [],
        "serve": [],
    },
    "lifecycle": {
        "publish": ["session_status"],
        "subscribe": ["gate_status"],
        "query": [],
        "serve": [
            "rpc_open_session",
            "rpc_step_request",
            "rpc_run_request",
            "rpc_close_session",
        ],
    },
    "mission-authority": {
        "publish": ["mission_lease", "mission_revocation"],
        "subscribe": ["gate_challenge", "gate_status"],
        "query": [],
        "serve": [],
    },
    "observer": {
        "publish": [],
        "subscribe": [
            "final_command",
            "state_pose",
            "session_status",
            "decision_evidence",
            "gate_status",
            "application_evidence",
        ],
        "query": [],
        "serve": [],
    },
    "robot-crebain": {
        "publish": ["state_pose", "application_evidence"],
        "subscribe": ["final_command", "session_status", "gate_status"],
        "query": [
            "rpc_open_session",
            "rpc_step_request",
            "rpc_run_request",
            "rpc_close_session",
        ],
        "serve": [],
    },
}
OP_RULES = {
    # Zenoh 1.9 authorizes a routed message independently on the sender's
    # ingress and the receiver's egress. Declaration propagation is likewise
    # directional; do not collapse these into one bidirectional rule.
    "publish": {
        "ingress": ["put"],
        "egress": ["declare_subscriber"],
    },
    "subscribe": {
        "ingress": ["declare_subscriber"],
        "egress": ["put"],
    },
    "query": {
        "ingress": ["query"],
        "egress": ["reply"],
    },
    "serve": {
        "ingress": ["reply"],
        "egress": ["query"],
    },
}
FORBIDDEN_SOURCE_FIELD = re.compile(
    r"(?:private|password|secret|token|credential|key_path|certificate_path)", re.IGNORECASE
)
PEM_PRIVATE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
SAFE_CN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,126}[A-Za-z0-9])?")
TLS_ENDPOINT = re.compile(r"tls/([A-Za-z0-9.-]+):([0-9]{1,5})")


class ProfileError(ValueError):
    """The source profile is unsafe, ambiguous, or outside the fixed schema."""


class VerificationError(ValueError):
    """A rendered Zenoh configuration violates the expected security shape."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _expect_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProfileError(f"{label} fields differ: missing={missing}, extra={extra}")


def _is_safe_segment(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 128:
        return False
    return all(character.isascii() and (character.isalnum() or character in "._-:") for character in value)


def _is_safe_realm(value: object) -> bool:
    # Haldir signs realm as `AsciiId<64>`, so it must remain one route segment.
    return _is_safe_segment(value) and len(value.encode("utf-8")) <= 64


def _scan_source(value: Any, path: str = "profile") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if FORBIDDEN_SOURCE_FIELD.search(key):
                raise ProfileError(f"source profile contains forbidden secret field at {path}.{key}")
            _scan_source(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _scan_source(nested, f"{path}[{index}]")
    elif isinstance(value, str) and PEM_PRIVATE.search(value):
        raise ProfileError(f"source profile contains inline private key material at {path}")


def expected_routes(realm: str, session_id: str) -> dict[str, str]:
    base = f"{realm}/session/{session_id}"
    return {
        "admission_record": f"{base}/haldir/authority/admission/record",
        "admission_revocation": f"{base}/haldir/authority/admission/revocation",
        "application_evidence": f"{base}/haldir/application",
        "controller_a_intent": f"{base}/haldir/intent/controller-a",
        "controller_b_intent": f"{base}/haldir/intent/controller-b",
        "decision_evidence": f"{base}/haldir/decision",
        "final_command": f"{base}/command",
        "gate_challenge": f"{base}/haldir/challenge",
        "gate_status": f"{base}/haldir/status",
        "mission_lease": f"{base}/haldir/authority/mission/lease",
        "mission_revocation": f"{base}/haldir/authority/mission/revocation",
        "rpc_close_session": f"{realm}/rpc/close_session",
        "rpc_open_session": f"{realm}/rpc/open_session",
        "rpc_run_request": f"{realm}/rpc/run_request",
        "rpc_step_request": f"{realm}/rpc/step_request",
        "session_status": f"{base}/haldir/lifecycle/status",
        "state_pose": f"{base}/sensor/pose",
    }


def validate_profile(profile: dict[str, Any]) -> None:
    """Validate the closed source schema and the complete audited ACL matrix."""
    _scan_source(profile)
    _expect_exact_keys(profile, PROFILE_KEYS, "profile")
    if profile["schema_version"] != 1:
        raise ProfileError("schema_version must be exactly 1")
    if profile["profile_id"] != "haldir-secure-reference-v1":
        raise ProfileError("unexpected profile_id")
    if profile["zenoh_version"] != "1.9.0":
        raise ProfileError("zenoh_version must be exactly 1.9.0")
    if not _is_safe_realm(profile["realm"]):
        raise ProfileError("realm contains an unsafe Zenoh key segment")
    if not _is_safe_segment(profile["session_id"]):
        raise ProfileError("session_id is not one safe Zenoh key segment")
    if profile["controllers"] != CONTROLLERS:
        raise ProfileError("controllers must be the exact two-controller fixture")

    router = profile["router"]
    if not isinstance(router, dict):
        raise ProfileError("router must be an object")
    _expect_exact_keys(router, ROUTER_KEYS, "router")
    if router["image"] != ZENOH_IMAGE:
        raise ProfileError("router image must equal the reviewed immutable Zenoh 1.9.0 digest")
    endpoint_hosts: dict[str, str] = {}
    for endpoint_name in ("client_endpoint", "listen_endpoint"):
        endpoint = router[endpoint_name]
        match = TLS_ENDPOINT.fullmatch(endpoint) if isinstance(endpoint, str) else None
        if match is None or not 1 <= int(match.group(2)) <= 65535:
            raise ProfileError(f"router.{endpoint_name} must be one valid TLS endpoint")
        endpoint_hosts[endpoint_name] = match.group(1)
    if not isinstance(router["certificate_common_name"], str) or not SAFE_CN.fullmatch(
        router["certificate_common_name"]
    ):
        raise ProfileError("router certificate common name is unsafe")
    if endpoint_hosts["client_endpoint"] != router["certificate_common_name"]:
        raise ProfileError("client TLS endpoint host must equal the router certificate common name")

    routes = profile["routes"]
    if not isinstance(routes, dict):
        raise ProfileError("routes must be an object")
    wanted_routes = expected_routes(profile["realm"], profile["session_id"])
    if routes != wanted_routes:
        raise ProfileError("routes must equal the exact derived single-session route set")
    if any(not _is_exact_key_expression(route) for route in routes.values()):
        raise ProfileError("every route must be an exact, wildcard-free key expression")

    principals = profile["principals"]
    if not isinstance(principals, dict) or set(principals) != set(PRINCIPAL_ROLES):
        raise ProfileError("principal set differs from the fixed role set")
    common_names = [router["certificate_common_name"]]
    for principal_id, expected_role in PRINCIPAL_ROLES.items():
        principal = principals[principal_id]
        if not isinstance(principal, dict):
            raise ProfileError(f"principal {principal_id} must be an object")
        _expect_exact_keys(principal, PRINCIPAL_KEYS, f"principal {principal_id}")
        if principal["role"] != expected_role:
            raise ProfileError(f"principal {principal_id} has the wrong role")
        common_name = principal["certificate_common_name"]
        if not isinstance(common_name, str) or not SAFE_CN.fullmatch(common_name):
            raise ProfileError(f"principal {principal_id} common name is unsafe")
        common_names.append(common_name)
        expected_permissions = EXPECTED_MATRIX[principal_id]
        for operation in OP_RULES:
            route_ids = principal[operation]
            if route_ids != expected_permissions[operation]:
                raise ProfileError(
                    f"principal {principal_id} {operation} grants differ from audited matrix"
                )
            if any(route_id not in routes for route_id in route_ids):
                raise ProfileError(f"principal {principal_id} references an unknown route")
    if len(common_names) != len(set(common_names)):
        raise ProfileError("certificate common names must be globally distinct")
    for principal_id, expected_common_name in EXPECTED_CNS.items():
        if principals[principal_id]["certificate_common_name"] != expected_common_name:
            raise ProfileError(f"principal {principal_id} common name differs from its exact binding")


def load_profile(path: Path = DEFAULT_PROFILE) -> dict[str, Any]:
    """Load strict JSON, rejecting duplicate keys before schema validation."""
    try:
        profile = json.loads(path.read_text(), object_pairs_hook=_reject_duplicate_keys)
    except OSError as error:
        raise ProfileError(f"cannot read profile: {error}") from error
    except json.JSONDecodeError as error:
        raise ProfileError(f"profile is not strict JSON: {error}") from error
    if not isinstance(profile, dict):
        raise ProfileError("profile root must be an object")
    validate_profile(profile)
    return profile


def _is_exact_key_expression(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not value.startswith("/")
        and not value.endswith("/")
        and "//" not in value
        and all(
            character.isascii()
            and not character.isspace()
            and ord(character) >= 32
            and ord(character) != 127
            and character not in "$*#?"
            for character in value
        )
    )


def _identity_path(name: str) -> str:
    return f"{IDENTITY_ROOT}/{name}"


def router_config(profile: dict[str, Any]) -> dict[str, Any]:
    """Render a strict-JSON subset of a Zenoh 1.9 router JSON5 configuration."""
    validate_profile(profile)
    rules: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []
    subjects: list[dict[str, Any]] = []
    routes = profile["routes"]
    rpc_queryable = f"{profile['realm']}/rpc/*"
    for principal_id in sorted(profile["principals"]):
        principal = profile["principals"][principal_id]
        subjects.append(
            {
                "cert_common_names": [principal["certificate_common_name"]],
                "id": principal_id,
            }
        )
        rule_ids: list[str] = []
        for operation in ("publish", "subscribe", "query", "serve"):
            route_ids = principal[operation]
            if not route_ids:
                continue
            for flow, messages in OP_RULES[operation].items():
                rule_id = f"allow-{principal_id}-{operation}-{flow}"
                rule_ids.append(rule_id)
                rules.append(
                    {
                        "flows": [flow],
                        "id": rule_id,
                        "key_exprs": [routes[route_id] for route_id in route_ids],
                        "messages": messages,
                        "permission": "allow",
                    }
                )
            if operation in {"query", "serve"}:
                # Pinned NCP v0.8 serves one `{realm}/rpc/*` queryable while
                # callers query four exact verb routes. Admit the wildcard only
                # for queryable-declaration propagation, never query or reply.
                flow = "egress" if operation == "query" else "ingress"
                rule_id = f"allow-{principal_id}-{operation}-queryable-{flow}"
                rule_ids.append(rule_id)
                rules.append(
                    {
                        "flows": [flow],
                        "id": rule_id,
                        "key_exprs": [rpc_queryable],
                        "messages": ["declare_queryable"],
                        "permission": "allow",
                    }
                )
        policies.append(
            {
                "id": f"policy-{principal_id}",
                "rules": rule_ids,
                "subjects": [principal_id],
            }
        )
    return {
        "access_control": {
            "default_permission": "deny",
            "enabled": True,
            "policies": policies,
            "rules": rules,
            "subjects": subjects,
        },
        "adminspace": {"enabled": False},
        "connect": {"endpoints": []},
        "listen": {
            "endpoints": [profile["router"]["listen_endpoint"]],
            "exit_on_failure": True,
        },
        "mode": "router",
        "plugins": {},
        "plugins_loading": {"enabled": False},
        "scouting": {
            "gossip": {"enabled": False},
            "multicast": {"enabled": False},
        },
        "transport": {
            "link": {
                "rx": {
                    "buffer_size": 65535,
                    "max_message_size": 32768,
                },
                "tx": {
                    "queue": {
                        "congestion_control": {
                            "block": {"wait_before_close": 50000}
                        }
                    }
                },
                "tls": {
                    "close_link_on_expiration": True,
                    "enable_mtls": True,
                    "listen_certificate": _identity_path("router.cert.pem"),
                    "listen_private_key": _identity_path("router.key.pem"),
                    "root_ca_certificate": _identity_path("ca.pem"),
                }
            },
            "shared_memory": {"enabled": False},
        },
    }


def router_launch(profile: dict[str, Any]) -> dict[str, Any]:
    """Pin the official daemon launch that reasserts settings it overrides."""
    validate_profile(profile)
    return {
        "argv": [
            "--config",
            ROUTER_CONFIG_PATH,
            "--adminspace-permissions",
            "none",
            "--cfg=adminspace/enabled:false",
            "--cfg=plugins_loading/enabled:false",
        ],
        "config_path": ROUTER_CONFIG_PATH,
        "image": profile["router"]["image"],
    }


def client_config(profile: dict[str, Any], principal_id: str) -> dict[str, Any]:
    """Render one TLS-only, no-listener, no-discovery Zenoh 1.9 client."""
    validate_profile(profile)
    if principal_id not in profile["principals"]:
        raise ProfileError(f"unknown principal: {principal_id}")
    return {
        "adminspace": {"enabled": False},
        "connect": {
            "endpoints": [profile["router"]["client_endpoint"]],
            "exit_on_failure": True,
            "timeout_ms": 10000,
        },
        "listen": {"endpoints": []},
        "mode": "client",
        "plugins": {},
        "plugins_loading": {"enabled": False},
        "scouting": {
            "gossip": {"enabled": False},
            "multicast": {"enabled": False},
        },
        "transport": {
            "link": {
                "rx": {
                    "buffer_size": 65535,
                    "max_message_size": 32768,
                },
                "tx": {
                    "queue": {
                        "congestion_control": {
                            "block": {"wait_before_close": 50000}
                        }
                    }
                },
                "tls": {
                    "close_link_on_expiration": True,
                    "connect_certificate": _identity_path(f"{principal_id}.cert.pem"),
                    "connect_private_key": _identity_path(f"{principal_id}.key.pem"),
                    "enable_mtls": True,
                    "root_ca_certificate": _identity_path("ca.pem"),
                    "verify_name_on_connect": True,
                }
            },
            "shared_memory": {"enabled": False},
        },
    }


def canonical_json(value: Any) -> bytes:
    """Stable strict JSON bytes, also accepted as JSON5 by Zenoh."""
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def render_bundle(profile: dict[str, Any]) -> dict[str, bytes]:
    """Return every deterministic configuration and its checksum manifest."""
    validate_profile(profile)
    files = {
        "router-launch.json": canonical_json(router_launch(profile)),
        "router.json5": canonical_json(router_config(profile)),
    }
    for principal_id in sorted(profile["principals"]):
        files[f"clients/{principal_id}.json"] = canonical_json(
            client_config(profile, principal_id)
        )
    manifest = {
        "files": {
            name: hashlib.sha256(content).hexdigest() for name, content in sorted(files.items())
        },
        "profile_id": profile["profile_id"],
        "profile_sha256": hashlib.sha256(canonical_json(profile)).hexdigest(),
        "renderer_schema_version": 1,
        "router_image": profile["router"]["image"],
        "zenoh_version": profile["zenoh_version"],
    }
    files["render-manifest.json"] = canonical_json(manifest)
    return files


def write_bundle(output: Path, files: dict[str, bytes]) -> None:
    """Write one previously rendered bundle without embedding key material."""
    if any(
        Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or "\\" in relative
        for relative in files
    ):
        raise VerificationError("rendered bundle contains an unsafe output path")
    expected = set(files)
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise VerificationError("render output must be a real directory")
    if output.is_dir():
        for path in output.rglob("*"):
            if path.is_symlink():
                raise VerificationError("render output must not contain symlinks")
        existing = {
            str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()
        }
        if not existing <= expected:
            raise VerificationError("render output contains an unexpected stale file")
    ordered = sorted(name for name in files if name != "render-manifest.json")
    if "render-manifest.json" in files:
        ordered.append("render-manifest.json")
    for relative in ordered:
        content = files[relative]
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def _nested(value: dict[str, Any], *path: str) -> Any:
    current: Any = value
    for part in path:
        if not isinstance(current, dict) or part not in current:
            raise VerificationError(f"missing configuration path: {'/'.join(path)}")
        current = current[part]
    return current


def _verify_common_transport(config: dict[str, Any], mode: str) -> None:
    if config.get("mode") != mode:
        raise VerificationError(f"mode must be {mode}")
    if _nested(config, "scouting", "multicast", "enabled") is not False:
        raise VerificationError("multicast scouting must be disabled")
    if _nested(config, "scouting", "gossip", "enabled") is not False:
        raise VerificationError("gossip scouting must be disabled")
    if _nested(config, "transport", "shared_memory", "enabled") is not False:
        raise VerificationError("shared memory must be disabled for this profile")
    if _nested(config, "adminspace", "enabled") is not False:
        raise VerificationError("admin space must be disabled")
    if config.get("plugins") != {} or config.get("plugins_loading") != {"enabled": False}:
        raise VerificationError("plugin loading/configuration must be disabled and empty")


def verify_router(profile: dict[str, Any], config: dict[str, Any]) -> None:
    """Independently reconstruct and verify the router's effective ACL grants."""
    validate_profile(profile)
    _verify_common_transport(config, "router")
    if config.get("connect") != {"endpoints": []}:
        raise VerificationError("router must not connect to another endpoint")
    listen = config.get("listen")
    expected_listen = {
        "endpoints": [profile["router"]["listen_endpoint"]],
        "exit_on_failure": True,
    }
    if listen != expected_listen or not all(
        endpoint.startswith("tls/") for endpoint in listen["endpoints"]
    ):
        raise VerificationError("router must listen only on its exact TLS endpoint")
    tls = _nested(config, "transport", "link", "tls")
    required_tls = {
        "close_link_on_expiration": True,
        "enable_mtls": True,
        "listen_certificate": _identity_path("router.cert.pem"),
        "listen_private_key": _identity_path("router.key.pem"),
        "root_ca_certificate": _identity_path("ca.pem"),
    }
    if tls != required_tls:
        raise VerificationError("router TLS/mTLS identity settings differ from the fixed profile")
    if _nested(config, "transport", "link", "rx") != {
        "buffer_size": 65535,
        "max_message_size": 32768,
    }:
        raise VerificationError("router receive/defragmentation bounds differ")
    if _nested(
        config,
        "transport",
        "link",
        "tx",
        "queue",
        "congestion_control",
        "block",
    ) != {"wait_before_close": 50000}:
        raise VerificationError("router blocking-publication wait bound differs")

    acl = config.get("access_control")
    if not isinstance(acl, dict) or acl.get("enabled") is not True:
        raise VerificationError("access control must be enabled")
    if acl.get("default_permission") != "deny":
        raise VerificationError("access control must default deny")
    rules = acl.get("rules")
    subjects = acl.get("subjects")
    policies = acl.get("policies")
    if not all(isinstance(value, list) for value in (rules, subjects, policies)):
        raise VerificationError("ACL rules, subjects, and policies must be lists")

    subject_cns: dict[str, str] = {}
    for subject in subjects:
        if not isinstance(subject, dict) or set(subject) != {"id", "cert_common_names"}:
            raise VerificationError("each ACL subject must bind exactly one certificate CN")
        subject_id = subject["id"]
        names = subject["cert_common_names"]
        if (
            not isinstance(subject_id, str)
            or not isinstance(names, list)
            or len(names) != 1
            or not isinstance(names[0], str)
        ):
            raise VerificationError("each ACL subject must bind exactly one certificate CN")
        if subject_id in subject_cns or names[0] in subject_cns.values():
            raise VerificationError("ACL subject IDs and certificate CNs must be unique")
        subject_cns[subject_id] = names[0]
    expected_cns = {
        principal_id: principal["certificate_common_name"]
        for principal_id, principal in profile["principals"].items()
    }
    if subject_cns != expected_cns:
        raise VerificationError("ACL subjects differ from the source principal bindings")

    rule_map: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            raise VerificationError("ACL rule must be an object")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or rule_id in rule_map:
            raise VerificationError("ACL rule IDs must be unique strings")
        flows = rule.get("flows")
        if (
            rule.get("permission") != "allow"
            or not isinstance(flows, list)
            or len(flows) != 1
            or flows[0] not in {"ingress", "egress"}
        ):
            raise VerificationError("ACL rules must grant one exact direction")
        key_exprs = rule.get("key_exprs")
        messages = rule.get("messages")
        if not isinstance(key_exprs, list) or not key_exprs:
            raise VerificationError("ACL rule key expressions must be nonempty")
        if not isinstance(messages, list) or not messages:
            raise VerificationError("ACL rule messages must be nonempty")
        if any(not isinstance(message, str) for message in messages):
            raise VerificationError("ACL rule messages must be strings")
        rpc_queryable = f"{profile['realm']}/rpc/*"
        declaration_glob = (
            key_exprs == [rpc_queryable] and messages == ["declare_queryable"]
        )
        if not declaration_glob and any(not _is_exact_key_expression(key) for key in key_exprs):
            raise VerificationError(
                "ACL key expressions must be exact except the reviewed RPC queryable declaration"
            )
        rule_map[rule_id] = rule

    actual_grants: set[tuple[str, str, str, str]] = set()
    policy_ids: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict) or set(policy) != {"id", "rules", "subjects"}:
            raise VerificationError("ACL policy has an unexpected shape")
        if not isinstance(policy["id"], str):
            raise VerificationError("ACL policy IDs must be strings")
        if policy["id"] in policy_ids:
            raise VerificationError("ACL policy IDs must be unique")
        policy_ids.add(policy["id"])
        if not isinstance(policy["rules"], list) or not isinstance(policy["subjects"], list):
            raise VerificationError("ACL policy references must be lists")
        if any(not isinstance(value, str) for value in policy["rules"] + policy["subjects"]):
            raise VerificationError("ACL policy references must be strings")
        for principal_id in policy["subjects"]:
            if principal_id not in subject_cns:
                raise VerificationError("ACL policy references an unknown subject")
            for rule_id in policy["rules"]:
                rule = rule_map.get(rule_id)
                if rule is None:
                    raise VerificationError("ACL policy references an unknown rule")
                for message in rule["messages"]:
                    for key in rule["key_exprs"]:
                        actual_grants.add((principal_id, message, rule["flows"][0], key))

    expected_grants: set[tuple[str, str, str, str]] = set()
    routes = profile["routes"]
    rpc_queryable = f"{profile['realm']}/rpc/*"
    for principal_id, permissions in EXPECTED_MATRIX.items():
        for operation, flow_rules in OP_RULES.items():
            for route_id in permissions[operation]:
                for flow, messages in flow_rules.items():
                    for message in messages:
                        expected_grants.add((principal_id, message, flow, routes[route_id]))
            if operation in {"query", "serve"} and permissions[operation]:
                flow = "egress" if operation == "query" else "ingress"
                expected_grants.add(
                    (principal_id, "declare_queryable", flow, rpc_queryable)
                )
    if actual_grants != expected_grants:
        raise VerificationError("effective ACL grants differ from the audited matrix")

    command = routes["final_command"]
    command_writers = {
        principal
        for principal, message, flow, key in actual_grants
        if key == command and message == "put" and flow == "ingress"
    }
    if command_writers != {"gate"}:
        raise VerificationError("only Gate may PUT the exact base command route")
    command_receivers = {
        principal
        for principal, message, flow, key in actual_grants
        if key == command and message == "put" and flow == "egress"
    }
    if command_receivers != {"observer", "robot-crebain"}:
        raise VerificationError("only robot and observer may receive the final command route")
    for _, _, _, key in actual_grants:
        if "/command" in key and key != command:
            raise VerificationError("named, wildcard, or alternate command authority is forbidden")


def verify_client(profile: dict[str, Any], principal_id: str, config: dict[str, Any]) -> None:
    """Verify a role client cannot listen, scout, use plaintext, or omit identity."""
    validate_profile(profile)
    if principal_id not in profile["principals"]:
        raise VerificationError(f"unknown client principal: {principal_id}")
    _verify_common_transport(config, "client")
    if config.get("listen") != {"endpoints": []}:
        raise VerificationError("clients must expose no listen endpoint")
    connect = config.get("connect")
    expected_connect = {
        "endpoints": [profile["router"]["client_endpoint"]],
        "exit_on_failure": True,
        "timeout_ms": 10000,
    }
    if connect != expected_connect or not all(
        endpoint.startswith("tls/") for endpoint in connect["endpoints"]
    ):
        raise VerificationError("client must connect only to the exact TLS router endpoint")
    tls = _nested(config, "transport", "link", "tls")
    expected_tls = {
        "close_link_on_expiration": True,
        "connect_certificate": _identity_path(f"{principal_id}.cert.pem"),
        "connect_private_key": _identity_path(f"{principal_id}.key.pem"),
        "enable_mtls": True,
        "root_ca_certificate": _identity_path("ca.pem"),
        "verify_name_on_connect": True,
    }
    if tls != expected_tls:
        raise VerificationError("client TLS identity/name-verification settings differ")
    if config.get("plugins") != {} or config.get("plugins_loading") != {"enabled": False}:
        raise VerificationError("client plugin loading/configuration must be disabled and empty")
    if _nested(config, "transport", "link", "rx") != {
        "buffer_size": 65535,
        "max_message_size": 32768,
    }:
        raise VerificationError("client receive/defragmentation bounds differ")
    if _nested(
        config,
        "transport",
        "link",
        "tx",
        "queue",
        "congestion_control",
        "block",
    ) != {"wait_before_close": 50000}:
        raise VerificationError("client blocking-publication wait bound differs")


def verify_bundle(profile: dict[str, Any], files: dict[str, bytes]) -> None:
    """Verify all rendered files, deterministic checksums, and expected filenames."""
    validate_profile(profile)
    expected_names = {"router-launch.json", "router.json5", "render-manifest.json"} | {
        f"clients/{principal_id}.json" for principal_id in profile["principals"]
    }
    if set(files) != expected_names:
        raise VerificationError("rendered bundle filename set differs from the fixed role set")
    try:
        router = json.loads(files["router.json5"], object_pairs_hook=_reject_duplicate_keys)
        launch = json.loads(
            files["router-launch.json"], object_pairs_hook=_reject_duplicate_keys
        )
        clients = {
            principal_id: json.loads(
                files[f"clients/{principal_id}.json"], object_pairs_hook=_reject_duplicate_keys
            )
            for principal_id in profile["principals"]
        }
        manifest = json.loads(
            files["render-manifest.json"], object_pairs_hook=_reject_duplicate_keys
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ProfileError) as error:
        raise VerificationError(f"rendered bundle is not strict duplicate-free JSON: {error}") from error
    if (
        not isinstance(router, dict)
        or not isinstance(launch, dict)
        or not all(isinstance(client, dict) for client in clients.values())
    ):
        raise VerificationError("rendered configurations must have object roots")
    if launch != router_launch(profile):
        raise VerificationError("router launch command differs from the pinned daemon profile")
    verify_router(profile, router)
    for principal_id, client in clients.items():
        verify_client(profile, principal_id, client)
    expected_hashes = {
        name: hashlib.sha256(content).hexdigest()
        for name, content in sorted(files.items())
        if name != "render-manifest.json"
    }
    expected_manifest = {
        "files": expected_hashes,
        "profile_id": profile["profile_id"],
        "profile_sha256": hashlib.sha256(canonical_json(profile)).hexdigest(),
        "renderer_schema_version": 1,
        "router_image": profile["router"]["image"],
        "zenoh_version": profile["zenoh_version"],
    }
    if manifest != expected_manifest:
        raise VerificationError("render manifest digest set is inconsistent")
    if files != render_bundle(profile):
        raise VerificationError("rendered bytes differ from the deterministic closed configuration")
