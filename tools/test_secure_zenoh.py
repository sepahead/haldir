#!/usr/bin/env python3
"""Standard-library adversarial tests for the secure Zenoh profile tooling."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_zenoh import (  # noqa: E402
    DEFAULT_PROFILE,
    ProfileError,
    VerificationError,
    canonical_json,
    load_profile,
    render_bundle,
    validate_profile,
    verify_bundle,
    write_bundle,
)


class SecureZenohProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile(DEFAULT_PROFILE)

    def test_profile_and_rendered_bundle_pass(self) -> None:
        files = render_bundle(self.profile)
        verify_bundle(self.profile, files)
        self.assertEqual(len(files), 11)
        router = json.loads(files["router.json5"])
        self.assertNotIn(
            "delete",
            {
                message
                for rule in router["access_control"]["rules"]
                for message in rule["messages"]
            },
        )
        final_command = self.profile["routes"]["final_command"]
        command_rules = [
            rule
            for rule in router["access_control"]["rules"]
            if final_command in rule["key_exprs"]
        ]
        self.assertIn(
            ("allow-gate-publish-ingress", ["put"], ["ingress"]),
            [(rule["id"], rule["messages"], rule["flows"]) for rule in command_rules],
        )
        for principal in ("robot-crebain", "observer"):
            self.assertIn(
                (f"allow-{principal}-subscribe-egress", ["put"], ["egress"]),
                [(rule["id"], rule["messages"], rule["flows"]) for rule in command_rules],
            )
        self.assertTrue(all(len(rule["flows"]) == 1 for rule in router["access_control"]["rules"]))
        rpc_queryable = f"{self.profile['realm']}/rpc/*"
        wildcard_rules = [
            rule
            for rule in router["access_control"]["rules"]
            if any("*" in key for key in rule["key_exprs"])
        ]
        self.assertTrue(wildcard_rules)
        self.assertTrue(
            all(
                rule["key_exprs"] == [rpc_queryable]
                and rule["messages"] == ["declare_queryable"]
                for rule in wildcard_rules
            )
        )

    def test_fixed_critical_grant_oracle_matches_pinned_ncp_semantics(self) -> None:
        """Independent literals for command, intent, and NCP RPC directionality."""
        router = json.loads(render_bundle(self.profile)["router.json5"])
        rules = {rule["id"]: rule for rule in router["access_control"]["rules"]}
        policies = {
            policy["subjects"][0]: policy["rules"]
            for policy in router["access_control"]["policies"]
        }
        grants = set()
        for principal, rule_ids in policies.items():
            for rule_id in rule_ids:
                rule = rules[rule_id]
                for message in rule["messages"]:
                    for key in rule["key_exprs"]:
                        grants.add((principal, message, rule["flows"][0], key))

        base = "haldir-ncp/session/uav-1"
        rpc_glob = "haldir-ncp/rpc/*"
        rpc_routes = {
            "haldir-ncp/rpc/open_session",
            "haldir-ncp/rpc/step_request",
            "haldir-ncp/rpc/run_request",
            "haldir-ncp/rpc/close_session",
        }
        required = {
            ("gate", "put", "ingress", f"{base}/command"),
            ("robot-crebain", "put", "egress", f"{base}/command"),
            ("observer", "put", "egress", f"{base}/command"),
            (
                "controller-a",
                "put",
                "ingress",
                f"{base}/haldir/intent/controller-a",
            ),
            ("gate", "put", "egress", f"{base}/haldir/intent/controller-a"),
            ("lifecycle", "declare_queryable", "ingress", rpc_glob),
            ("robot-crebain", "declare_queryable", "egress", rpc_glob),
        }
        self.assertTrue(required <= grants)
        for route in rpc_routes:
            self.assertIn(("robot-crebain", "query", "ingress", route), grants)
            self.assertIn(("lifecycle", "query", "egress", route), grants)
            self.assertIn(("lifecycle", "reply", "ingress", route), grants)
            self.assertIn(("robot-crebain", "reply", "egress", route), grants)
        self.assertEqual(
            {
                principal
                for principal, message, flow, key in grants
                if message == "put" and flow == "ingress" and key == f"{base}/command"
            },
            {"gate"},
        )

    def test_render_is_deterministic_and_round_trips_from_disk(self) -> None:
        first = render_bundle(self.profile)
        second = render_bundle(copy.deepcopy(self.profile))
        self.assertEqual(first, second)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_bundle(root, first)
            read_back = {
                str(path.relative_to(root)): path.read_bytes()
                for path in sorted(root.rglob("*"))
                if path.is_file()
            }
        self.assertEqual(first, read_back)
        verify_bundle(self.profile, read_back)

    def test_rejects_unsafe_realm_session_and_route_drift(self) -> None:
        for field, value in (
            ("realm", "haldir/**"),
            ("realm", "haldir/ncp"),
            ("realm", "háldir"),
            ("session_id", "uav/other"),
        ):
            mutated = copy.deepcopy(self.profile)
            mutated[field] = value
            with self.assertRaises(ProfileError):
                validate_profile(mutated)
        mutated = copy.deepcopy(self.profile)
        mutated["routes"]["final_command"] += "/named"
        with self.assertRaises(ProfileError):
            validate_profile(mutated)

    def test_rejects_endpoint_options_and_router_name_mismatch(self) -> None:
        mutated = copy.deepcopy(self.profile)
        mutated["router"]["client_endpoint"] += "#password=embedded"
        with self.assertRaises(ProfileError):
            validate_profile(mutated)
        mutated = copy.deepcopy(self.profile)
        mutated["router"]["certificate_common_name"] = "another-router"
        with self.assertRaisesRegex(ProfileError, "endpoint host"):
            validate_profile(mutated)
        mutated = copy.deepcopy(self.profile)
        mutated["router"]["image"] = "docker.io/eclipse/zenoh:1.9.0"
        with self.assertRaisesRegex(ProfileError, "immutable"):
            validate_profile(mutated)

    def test_rejects_duplicate_common_name_and_widened_matrix(self) -> None:
        mutated = copy.deepcopy(self.profile)
        mutated["principals"]["controller-a"]["certificate_common_name"] = mutated[
            "principals"
        ]["gate"]["certificate_common_name"]
        with self.assertRaisesRegex(ProfileError, "globally distinct"):
            validate_profile(mutated)
        mutated = copy.deepcopy(self.profile)
        mutated["principals"]["controller-a"]["publish"].append("final_command")
        with self.assertRaises(ProfileError):
            validate_profile(mutated)

    def test_rejects_source_secret_fields_and_inline_private_key(self) -> None:
        mutated = copy.deepcopy(self.profile)
        mutated["private_key"] = "not-even-key-material"
        with self.assertRaisesRegex(ProfileError, "forbidden secret field"):
            validate_profile(mutated)
        mutated = copy.deepcopy(self.profile)
        mutated["profile_id"] = "-----BEGIN PRIVATE KEY-----"
        with self.assertRaisesRegex(ProfileError, "inline private key material"):
            validate_profile(mutated)

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text('{"schema_version": 1, "schema_version": 1}')
            with self.assertRaisesRegex(ProfileError, "duplicate JSON key"):
                load_profile(path)

    def test_rejects_default_allow_disabled_mtls_and_plaintext_router(self) -> None:
        for mutation in ("default_allow", "mtls_off", "plaintext", "bidirectional_rule"):
            files = render_bundle(self.profile)
            router = json.loads(files["router.json5"])
            if mutation == "default_allow":
                router["access_control"]["default_permission"] = "allow"
            elif mutation == "mtls_off":
                router["transport"]["link"]["tls"]["enable_mtls"] = False
            elif mutation == "plaintext":
                router["listen"]["endpoints"] = ["tcp/0.0.0.0:7447"]
            else:
                router["access_control"]["rules"][0]["flows"] = ["ingress", "egress"]
            files["router.json5"] = canonical_json(router)
            with self.assertRaises(VerificationError):
                verify_bundle(self.profile, files)

    def test_rejects_wildcard_or_non_gate_command_writer(self) -> None:
        files = render_bundle(self.profile)
        router = json.loads(files["router.json5"])
        gate_publish = next(
            rule
            for rule in router["access_control"]["rules"]
            if rule["id"] == "allow-gate-publish-ingress"
        )
        gate_publish["key_exprs"][0] += "/**"
        files["router.json5"] = canonical_json(router)
        with self.assertRaisesRegex(VerificationError, "reviewed RPC"):
            verify_bundle(self.profile, files)

        files = render_bundle(self.profile)
        router = json.loads(files["router.json5"])
        controller_publish = next(
            rule
            for rule in router["access_control"]["rules"]
            if rule["id"] == "allow-controller-a-publish-ingress"
        )
        controller_publish["key_exprs"].append(self.profile["routes"]["final_command"])
        files["router.json5"] = canonical_json(router)
        with self.assertRaisesRegex(VerificationError, "audited matrix"):
            verify_bundle(self.profile, files)

        files = render_bundle(self.profile)
        router = json.loads(files["router.json5"])
        gate_publish = next(
            rule
            for rule in router["access_control"]["rules"]
            if rule["id"] == "allow-gate-publish-ingress"
        )
        gate_publish["messages"].append("delete")
        files["router.json5"] = canonical_json(router)
        with self.assertRaisesRegex(VerificationError, "audited matrix"):
            verify_bundle(self.profile, files)

    def test_rejects_client_listener_discovery_plaintext_and_name_bypass(self) -> None:
        cases = (
            "listener",
            "discovery",
            "plaintext",
            "name_bypass",
            "missing_key",
            "mtls_off",
            "rx_unbounded",
            "plugins",
        )
        for mutation in cases:
            files = render_bundle(self.profile)
            name = "clients/controller-a.json"
            client = json.loads(files[name])
            if mutation == "listener":
                client["listen"]["endpoints"] = ["tls/0.0.0.0:0"]
            elif mutation == "discovery":
                client["scouting"]["multicast"]["enabled"] = True
            elif mutation == "plaintext":
                client["connect"]["endpoints"] = ["tcp/haldir-router:7447"]
            elif mutation == "name_bypass":
                client["transport"]["link"]["tls"]["verify_name_on_connect"] = False
            elif mutation == "mtls_off":
                client["transport"]["link"]["tls"]["enable_mtls"] = False
            elif mutation == "rx_unbounded":
                client["transport"]["link"]["rx"]["max_message_size"] = 2**30
            elif mutation == "plugins":
                client["plugins"] = {"rogue": {}}
            else:
                del client["transport"]["link"]["tls"]["connect_private_key"]
            files[name] = canonical_json(client)
            with self.assertRaises(VerificationError, msg=mutation):
                verify_bundle(self.profile, files)

    def test_rejects_manifest_tampering_and_unexpected_files(self) -> None:
        files = render_bundle(self.profile)
        manifest = json.loads(files["render-manifest.json"])
        manifest["profile_sha256"] = "0" * 64
        files["render-manifest.json"] = canonical_json(manifest)
        with self.assertRaisesRegex(VerificationError, "manifest"):
            verify_bundle(self.profile, files)
        files = render_bundle(self.profile)
        files["clients/rogue.json"] = b"{}\n"
        with self.assertRaisesRegex(VerificationError, "filename set"):
            verify_bundle(self.profile, files)

        files = render_bundle(self.profile)
        launch = json.loads(files["router-launch.json"])
        launch["argv"].remove("--cfg=plugins_loading/enabled:false")
        files["router-launch.json"] = canonical_json(launch)
        with self.assertRaisesRegex(VerificationError, "launch command"):
            verify_bundle(self.profile, files)

    def test_rejects_unreviewed_rendered_configuration_fields(self) -> None:
        files = render_bundle(self.profile)
        router = json.loads(files["router.json5"])
        router["unreviewed_runtime_surface"] = {"enabled": True}
        files["router.json5"] = canonical_json(router)
        manifest = json.loads(files["render-manifest.json"])
        manifest["files"]["router.json5"] = hashlib.sha256(files["router.json5"]).hexdigest()
        files["render-manifest.json"] = canonical_json(manifest)
        with self.assertRaisesRegex(VerificationError, "closed configuration"):
            verify_bundle(self.profile, files)

    def test_renderer_rejects_stale_or_symlinked_output(self) -> None:
        files = render_bundle(self.profile)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "stale.json").write_text("{}")
            with self.assertRaisesRegex(VerificationError, "unexpected stale"):
                write_bundle(root, files)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(VerificationError, "real directory"):
                write_bundle(link, files)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(VerificationError, "unsafe output path"):
                write_bundle(Path(temporary), {"../escape.json": b"{}\n"})


if __name__ == "__main__":
    unittest.main()
