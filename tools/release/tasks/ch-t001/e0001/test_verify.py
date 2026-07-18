from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import random
import subprocess
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


MODULE_CACHE = []
INTEGRATION_CACHE = {}
PROTOCOL_CHAIN_CACHE = []
SNAPSHOT_MUTATION_CACHE = []


def verifier_module():
    if MODULE_CACHE:
        return MODULE_CACHE[0]
    path = Path(__file__).with_name("verify.py")
    spec = importlib.util.spec_from_file_location("ch_t001_registered_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("registered verifier module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    MODULE_CACHE.append(module)
    return module


def protocol_chain():
    if PROTOCOL_CHAIN_CACHE:
        return PROTOCOL_CHAIN_CACHE[0]
    module = verifier_module()
    repo = Path(__file__).resolve().parents[5]
    head = module._git(repo, ["rev-parse", "HEAD"], maximum=64).decode().strip()
    raw_freeze = module._git(
        repo,
        [
            "log",
            "--format=%H",
            "--diff-filter=A",
            "--",
            module.REGISTERED_TESTS_PATH,
        ],
        maximum=4096,
    )
    freeze_commits = raw_freeze.decode("ascii").splitlines()
    if not freeze_commits:
        result = (repo, None, head, [])
        PROTOCOL_CHAIN_CACHE.append(result)
        return result
    if len(freeze_commits) != 1:
        raise AssertionError("registered test path has multiple creation commits")
    freeze_commit = freeze_commits[0]
    raw_suffix = module._git(
        repo,
        ["rev-list", "--first-parent", "--reverse", f"{freeze_commit}..{head}"],
        maximum=64 * 1024,
    )
    result = (repo, freeze_commit, head, raw_suffix.decode("ascii").splitlines())
    PROTOCOL_CHAIN_CACHE.append(result)
    return result


def ensure_inventory_integration():
    module = verifier_module()
    repo, freeze_commit, head, suffix = protocol_chain()
    key = (str(repo), head)
    if key not in INTEGRATION_CACHE:
        INTEGRATION_CACHE[key] = (
            module.verify_inventory(repo, freeze_commit, suffix[0])
            if freeze_commit is not None and suffix
            else None
        )
    return INTEGRATION_CACHE[key]


def accepted_facts():
    ensure_inventory_integration()
    return verifier_module().test_fixture()


def freeze_surface_fixture(module):
    surfaces = []
    for path, status in module.EXPECTED_IMPLEMENTATION_PLAN.items():
        surfaces.append(
            {
                "path": path,
                "planned_status": status,
                "classification": module.EXPECTED_SURFACE_CLASSIFICATIONS[path],
                "claim_relevance": (
                    "PUBLIC_CLAIM_REVIEW_REQUIRED"
                    if path in module.EXPECTED_PUBLIC_SURFACES
                    else "SEMANTIC_REVIEW_REQUIRED"
                ),
                "in_repository_consumers": [module.VERIFIER_PATH],
                "external_consumers": [],
                "rationale": "Exact frozen affected-surface disposition.",
            }
        )
    return {
        "implementation_plan": dict(module.EXPECTED_IMPLEMENTATION_PLAN),
        "affected_surface_inventory": surfaces,
        "claim_outcomes": [
            {
                "public_surfaces": list(module.EXPECTED_PUBLIC_SURFACES),
                "migration": {
                    "required": True,
                    "paths": sorted(module.EXPECTED_IMPLEMENTATION_PLAN),
                    "disposition": "Apply the exact four-path implementation atomically.",
                },
                "rollback": {
                    "strategy": "RESTORE_EXACT_PRIOR_ACTIVATED_TREE_ENTRIES",
                    "paths": sorted(module.EXPECTED_IMPLEMENTATION_PLAN),
                    "verification": "GIT_MODE_TYPE_AND_OBJECT_IDENTITY",
                },
            }
        ],
    }


def snapshot_mutation_errors():
    if SNAPSHOT_MUTATION_CACHE:
        return SNAPSHOT_MUTATION_CACHE[0]
    module = verifier_module()
    repo, freeze_commit, _head, suffix = protocol_chain()
    if freeze_commit is None or not suffix:
        SNAPSHOT_MUTATION_CACHE.append(None)
        return None
    implementation_commit = suffix[0]
    errors = {}
    with tempfile.TemporaryDirectory(prefix="ch-t001-mutation-") as directory:
        clone_environment = module._environment(repo)
        clone_environment["GIT_CONFIG_GLOBAL"] = str(Path(directory) / "gitconfig")
        for safe_directory in (repo, repo / ".git"):
            configured = subprocess.run(
                [
                    "/usr/bin/git",
                    "config",
                    "--global",
                    "--add",
                    "safe.directory",
                    str(safe_directory),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=clone_environment,
                timeout=5,
                check=False,
            )
            if configured.returncode != 0 or configured.stdout or configured.stderr:
                raise AssertionError("protected clone configuration failed")
        clone = Path(directory) / "repo"
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "clone",
                "--no-local",
                "--no-hardlinks",
                str(repo),
                str(clone),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clone_environment,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode("utf-8", "replace"))
        module._git(clone, ["config", "commit.gpgsign", "false"])
        module._git(clone, ["config", "user.name", "CH-T001 Test Fixture"])
        module._git(clone, ["config", "user.email", "ch-t001-test@local.invalid"])

        def commit_mutation(path, transform):
            module._git(clone, ["read-tree", "--reset", "-u", implementation_commit])
            target = clone / path
            target.write_bytes(transform(target.read_bytes()))
            module._git(clone, ["add", "--", path])
            tree = module._git(clone, ["write-tree"], maximum=64).decode().strip()
            return (
                module._git(
                    clone,
                    ["commit-tree", tree, "-p", freeze_commit],
                    input_data=b"CH-T001 mutation fixture\n",
                    maximum=64,
                )
                .decode()
                .strip()
            )

        ledger_mutation = commit_mutation(
            module.LEDGER_PATH,
            lambda payload: payload.replace(b"schema_version,", b"schema_revision,", 1),
        )
        product_mutation = commit_mutation(
            module.PRODUCT_TOOL,
            lambda payload: payload + b"\n# mutation fixture\n",
        )
        for label, commit in (
            ("ledger", ledger_mutation),
            ("product", product_mutation),
        ):
            try:
                module.verify_inventory(clone, freeze_commit, commit)
            except module.VerificationError as error:
                errors[label] = str(error)
            else:
                raise AssertionError(f"{label} mutation was accepted")
    SNAPSHOT_MUTATION_CACHE.append(errors)
    return errors


class RegisteredVerifierTests(unittest.TestCase):
    def test_integration_inventory_entrypoint_executes_exact_available_chain(self):
        module = verifier_module()
        repo, freeze_commit, head, suffix = protocol_chain()
        if freeze_commit is not None and suffix:
            result = module.verify_inventory(repo, freeze_commit, suffix[0])
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["freeze_commit"], freeze_commit)
            self.assertEqual(result["implementation_commit"], suffix[0])
            self.assertGreater(result["unique_git_blobs"], 0)
        else:
            with self.assertRaises(module.VerificationError) as raised:
                module.verify_inventory(repo, head, head)
            self.assertEqual(str(raised.exception), "INVENTORY_ARGUMENT_COMMIT")

    def test_integration_repository_entrypoint_executes_exact_available_chain(self):
        module = verifier_module()
        repo, freeze_commit, head, suffix = protocol_chain()
        if freeze_commit is not None and len(suffix) >= 3:
            result = module.verify_repository(
                repo,
                freeze_commit,
                suffix[0],
                suffix[1],
                suffix[2],
                head,
            )
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["current_commit"], head)
        else:
            missing = "0" * 40
            with self.assertRaises(module.VerificationError) as raised:
                module.verify_repository(
                    repo,
                    missing,
                    missing,
                    missing,
                    missing,
                    missing,
                )
            self.assertEqual(str(raised.exception), "CHAIN_COMMIT_SET")

    def test_entrypoint_rejects_non_linear_chain(self):
        module = verifier_module()
        repo, freeze_commit, head, suffix = protocol_chain()
        if freeze_commit is not None and suffix:
            with self.assertRaises(module.VerificationError) as raised:
                module.verify_inventory(repo, suffix[0], freeze_commit)
            self.assertEqual(str(raised.exception), "INVENTORY_PARENT_CHAIN")
        else:
            with self.assertRaises(module.VerificationError) as raised:
                module.verify_inventory(repo, head, head)
            self.assertEqual(str(raised.exception), "INVENTORY_ARGUMENT_COMMIT")

    def test_entrypoint_rejects_mutated_ledger_snapshot(self):
        module = verifier_module()
        errors = snapshot_mutation_errors()
        if errors is not None:
            self.assertEqual(errors["ledger"], "LEDGER_HEADER")
        else:
            with self.assertRaises(module.VerificationError) as raised:
                module._parse_ledger(b"schema_revision\n")
            self.assertEqual(str(raised.exception), "LEDGER_ROW_COUNT")

    def test_entrypoint_rejects_product_snapshot_substitution(self):
        module = verifier_module()
        errors = snapshot_mutation_errors()
        if errors is not None:
            self.assertEqual(errors["product"], "INVENTORY_LEDGER_CAPTURE_MISMATCH")
        else:
            with self.assertRaises(module.VerificationError) as raised:
                module._validate_product_identities(b"mutated", b"mutated")
            self.assertEqual(str(raised.exception), "PRODUCT_SHA256_MISMATCH")

    def test_technique_property_metamorphic(self):
        module = verifier_module()
        generator = random.Random(0xC1A001)
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_-"
        for index in range(256):
            component = "".join(generator.choice(alphabet) for _ in range(24))
            path = f"fixtures/{index:03d}-{component}.txt"
            payload = (component + "\n").encode("ascii")
            self.assertEqual(module._canonical_path(module._canonical_path(path)), path)
            self.assertEqual(module._content(bytes(payload)), module._content(payload))
            self.assertEqual(module._content(payload)["content_kind"], "TEXT_UTF8")
            self.assertEqual(module._content(payload + b"\0")["content_kind"], "BINARY")

    def test_technique_differential_oracle(self):
        module = verifier_module()
        for payload in (b"", b"a", b"line one\nline two\n", bytes(range(256))):
            completed = subprocess.run(
                ["/usr/bin/git", "hash-object", "--stdin"],
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stderr, b"")
            self.assertEqual(
                module._git_blob_id(payload), completed.stdout.decode("ascii").strip()
            )

    def test_technique_fuzz(self):
        module = verifier_module()
        generator = random.Random(0xF022001)
        suffixes = (".bin", ".json", ".log", ".py", ".txt", "")
        for index in range(512):
            payload = bytes(generator.getrandbits(8) for _ in range(index % 257))
            path = f"fuzz/item-{index:04d}{suffixes[index % len(suffixes)]}"
            identity = module._content(payload)
            observed_format = module._format(path, identity, self_row=False)
            generated, generator_name = module._generated(path, self_row=False)
            self.assertIn(
                identity["content_kind"],
                {
                    "BINARY",
                    "TEXT_UTF8",
                    "TEXT_UTF8_WITH_ANSI_ESCAPE",
                    "TEXT_UTF8_WITH_CONTROLS",
                },
            )
            self.assertIsInstance(observed_format, str)
            self.assertIn(generated, {"YES", "NO", "UNKNOWN"})
            self.assertIsInstance(generator_name, str)

    def test_technique_mutation(self):
        module = verifier_module()
        mutations = {
            "CH-T001-N01": ("chain", "F>C>I>D"),
            "CH-T001-N02": ("i_count", 353),
            "CH-T001-N03": ("rows", 351),
            "CH-T001-N04": ("source_binding", False),
            "CH-T001-N05": ("capture_binding", False),
            "CH-T001-N06": ("self_binding", False),
            "CH-T001-N07": ("zero_extras", False),
            "CH-T001-N08": ("classifications", False),
            "CH-T001-N09": ("generated_links", False),
            "CH-T001-N10": ("independent", False),
            "CH-T001-N11": ("digests", False),
            "CH-T001-N12": ("no_fallback", False),
            "CH-T001-N13": ("output_binding", False),
            "CH-T001-N14": ("retention", False),
            "CH-T001-N15": ("regular_objects", False),
            "CH-T001-N16": ("typed_evidence", False),
            "CH-T001-N17": ("product_hashes", False),
            "CH-T001-N18": ("create_once", False),
            "CH-T001-N19": ("secret_ignore", False),
            "CH-T001-N20": ("unassigned", False),
        }
        self.assertEqual(tuple(mutations), module.CONTROL_IDS)
        for control_id, (field, replacement) in mutations.items():
            with self.subTest(control_id=control_id):
                facts = accepted_facts()
                facts[field] = replacement
                with self.assertRaises(module.VerificationError):
                    module.validate_control(control_id, facts)
        errors = snapshot_mutation_errors()
        if errors is not None:
            self.assertEqual(
                errors,
                {
                    "ledger": "LEDGER_HEADER",
                    "product": "INVENTORY_LEDGER_CAPTURE_MISMATCH",
                },
            )

    def test_technique_model(self):
        module = verifier_module()

        def model(payload):
            if b"\0" in payload:
                return "BINARY", "0"
            try:
                text = payload.decode("utf-8", "strict")
            except UnicodeDecodeError:
                return "BINARY", "0"
            controls = {
                character
                for character in text
                if character not in "\t\n\r"
                and module.unicodedata.category(character).startswith("C")
            }
            if controls == {"\x1b"}:
                kind = "TEXT_UTF8_WITH_ANSI_ESCAPE"
            elif controls:
                kind = "TEXT_UTF8_WITH_CONTROLS"
            else:
                kind = "TEXT_UTF8"
            return kind, str(len(text.splitlines()))

        corpus = (
            b"",
            b"plain\ntext\n",
            "deleted\u007f".encode("utf-8"),
            "next-line\u0085".encode("utf-8"),
            "override\u202e".encode("utf-8"),
            "soft\u00ad".encode("utf-8"),
            b"ansi \x1b[31mred\x1b[0m\n",
            b"bell\x07\n",
            b"nul\0byte",
            b"\xffinvalid",
        )
        for payload in corpus:
            expected_kind, expected_lines = model(payload)
            observed = module._content(payload)
            self.assertEqual(observed["content_kind"], expected_kind)
            self.assertEqual(observed["lines"], expected_lines)

    def test_technique_concurrency(self):
        module = verifier_module()
        payloads = [f"payload-{index}\n".encode("ascii") for index in range(64)]
        expected = [module._content(payload) for payload in payloads]
        repeated = payloads * 32
        with ThreadPoolExecutor(max_workers=8) as executor:
            observed = list(executor.map(module._content, repeated))
        self.assertEqual(
            observed,
            [expected[index % len(expected)] for index in range(len(repeated))],
        )

    def test_n01_exact_linear_chain_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N01", accepted_facts()))

    def test_n01_non_linear_chain_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["chain"] = "F>C>I>D"
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N01", facts)

    def test_n02_exact_source_and_implementation_trees_are_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N02", accepted_facts()))
        original = {"mode": "100644", "oid": "1" * 40}
        unchanged = {"mode": "100644", "oid": "1" * 40}
        modified = {"mode": "100644", "oid": "2" * 40}
        self.assertEqual(
            module._source_index_state(original, unchanged, self_row=False),
            "IDENTICAL",
        )
        self.assertEqual(
            module._source_index_state(original, modified, self_row=False),
            "MODIFIED_IN_INDEX",
        )

    def test_n02_extra_implementation_path_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["i_count"] = 353
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N02", facts)

    def test_n03_canonical_exact_ledger_schema_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N03", accepted_facts()))

    def test_n03_missing_ledger_column_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["schema"] = facts["schema"][:-1]
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N03", facts)

    def test_n04_exact_source_object_binding_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N04", accepted_facts()))

    def test_n04_substituted_source_identity_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["source_binding"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N04", facts)

    def test_n05_exact_capture_identity_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N05", accepted_facts()))

    def test_n05_index_current_contradiction_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["capture_binding"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N05", facts)

    def test_n06_external_self_binding_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N06", accepted_facts()))

    def test_n06_self_digest_claim_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["self_binding"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N06", facts)

    def test_n07_zero_unclassified_extras_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N07", accepted_facts()))

    def test_n07_hidden_filesystem_extra_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["zero_extras"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N07", facts)

    def test_n08_complete_language_and_format_classification_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N08", accepted_facts()))
        ansi = module._content(b"first \x1b[31mred\x1b[0m\nsecond\n")
        self.assertEqual(ansi["content_kind"], "TEXT_UTF8_WITH_ANSI_ESCAPE")
        self.assertEqual(ansi["lines"], "2")
        self.assertEqual(
            module._format("evidence/command.log", ansi, self_row=False),
            "ANSI_LOG_TEXT",
        )
        for text in (
            "deleted\u007f",
            "next-line\u0085",
            "override\u202e",
            "soft\u00ad",
        ):
            with self.subTest(text=text):
                classified = module._content(text.encode("utf-8"))
                self.assertEqual(classified["content_kind"], "TEXT_UTF8_WITH_CONTROLS")

    def test_n08_unknown_format_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["classifications"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N08", facts)
        binary = module._content(b"\x00not-json")
        self.assertEqual(
            module._format("evidence/result.json", binary, self_row=False),
            "BINARY_WITH_JSON_SUFFIX",
        )
        controlled = module._content(b"text\x07\n")
        self.assertEqual(
            module._format("evidence/result.txt", controlled, self_row=False),
            "CONTROL_BEARING_TEXT",
        )
        textual_binary = module._content(b"plain text\n")
        self.assertEqual(
            module._format("evidence/result.bin", textual_binary, self_row=False),
            "TEXT_WITH_BINARY_DATA_SUFFIX",
        )
        ansi_json = module._content(b"\x1b[0m\n")
        self.assertEqual(
            module._format("evidence/result.json", ansi_json, self_row=False),
            "ANSI_ESCAPE_WITH_JSON_SUFFIX",
        )

    def test_n09_bound_generated_provenance_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N09", accepted_facts()))
        self.assertEqual(
            module._generated("Cargo.lock", self_row=False),
            ("YES", "PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS"),
        )
        self.assertEqual(
            module._generated(
                "release/0.9.0/current-head/evidence/frozen.json",
                self_row=False,
            ),
            ("UNKNOWN", ""),
        )

    def test_independent_row_classification_matches_frozen_product_semantics(self):
        module = verifier_module()
        for path in (
            ".gitignore",
            "README.md",
            "contracts/vectors/README.md",
            "release/0.9.0/current-head/evidence/frozen.json",
            "release/0.9.0/current-head/handoff/MASTER_SHA256SUMS.txt",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    module._generated(path, self_row=False), ("UNKNOWN", "")
                )
        self.assertEqual(
            module._generated(module.LEDGER_PATH, self_row=True),
            ("YES", module.PRODUCT_TOOL),
        )
        self.assertEqual(
            module._generated("Cargo.lock", self_row=False),
            ("YES", "PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS"),
        )
        cases = {
            "crates/haldir-contracts/src/tests_contracts.rs": "TEST",
            "crates/haldir-deployment/src/tests.rs": "TEST",
            "tools/release/test_current_file_review_ledger.py": "TEST",
            "tools/release/tasks/ch-t001/e0001/test_verify.py": "TEST",
            "tools/release/verify-current-audit.py": "TOOLING",
            "crates/haldir-core/src/lib.rs": "RUST_SOURCE",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(
                    module._category(path, module._generated_reason(path)), expected
                )

    def test_n09_missing_generator_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["generated_links"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N09", facts)
        self.assertEqual(
            module._generated("generated/unproven.bin", self_row=False),
            ("UNKNOWN", ""),
        )

    def test_n10_independent_registered_oracle_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N10", accepted_facts()))

    def test_n10_product_helper_as_sole_oracle_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["independent"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N10", facts)

    def test_n11_domain_separated_digests_are_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N11", accepted_facts()))
        records = [{"path": "a", "oid": "0" * 40}]
        self.assertNotEqual(
            module._digest("source", records), module._digest("index", records)
        )

    def test_n11_cross_domain_digest_substitution_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["digests"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N11", facts)

    def test_n12_bounded_fail_closed_execution_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N12", accepted_facts()))
        self.assertEqual(module.MAX_LEDGER_BYTES, 4 * 1024 * 1024)
        self.assertEqual(module.MAX_LEDGER_BYTES, module.MAX_BLOB_BYTES)
        self.assertEqual(module.MAX_FIRST_PARENT_COMMITS, 1024)
        repo = Path(__file__).resolve().parents[5]
        self.assertEqual(module._bind_git_toplevel(repo), repo)
        with self.assertRaises(module.VerificationError):
            module._bind_git_toplevel(repo / "tools")

    def test_n12_capacity_fallback_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["no_fallback"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N12", facts)
        with self.assertRaises(module.VerificationError):
            module._canonical_path("../escape")
        with self.assertRaises(module.VerificationError):
            module._canonical_path(".git/objects/substitute")
        repo = Path(__file__).resolve().parents[5]
        with tempfile.TemporaryDirectory() as raw:
            symlink = Path(raw) / "repo-link"
            symlink.symlink_to(repo, target_is_directory=True)
            with self.assertRaises(module.VerificationError):
                module._bind_git_toplevel(symlink)
        for malformed in (
            b"relative\n",
            b"/tmp/repo\ntrailing\n",
            b"/tmp/repo\0suffix\n",
            "\u202e/tmp/repo\n".encode("utf-8"),
            b"/tmp/invalid-\xff\n",
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(module.VerificationError):
                    module._parse_git_toplevel(malformed)

    def test_n13_exact_runtime_output_binding_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N13", accepted_facts()))

    def test_n13_unbound_runtime_output_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["output_binding"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N13", facts)

    def test_n14_later_mutable_review_update_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N14", accepted_facts()))

    def test_n14_later_immutable_inventory_drift_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["retention"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N14", facts)

    def test_n15_regular_git_object_inventory_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N15", accepted_facts()))

    def test_n15_symlink_or_gitlink_inventory_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["regular_objects"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N15", facts)

    def test_product_fifo_type_swap_regression_is_frozen(self):
        module = verifier_module()
        self.assertIn(
            "test_regular_type_swap_to_fifo_never_blocks_open",
            module.EXPECTED_PRODUCT_TEST_IDS,
        )

    def test_product_padded_gitlink_grammar_regression_is_frozen(self):
        module = verifier_module()
        self.assertIn(
            "test_source_gitlink_size_field_uses_exact_padded_grammar",
            module.EXPECTED_PRODUCT_TEST_IDS,
        )

    def test_n16_typed_evidence_and_review_bodies_are_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N16", accepted_facts()))
        document = {
            "schema_id": module.EVIDENCE_SCHEMA_IDS["CH-T001-E01"],
            "evidence_id": "CH-T001-E01",
            "task_id": "CH-T001",
            "epoch": 1,
            "freeze_commit": "1" * 40,
            "implementation_commit": "2" * 40,
            "started_at_utc": "2026-07-15T12:00:00Z",
            "completed_at_utc": "2026-07-15T12:00:01Z",
            "result": "PASS",
        }
        self.assertEqual(
            module._validate_evidence_common(
                document, "CH-T001-E01", "1" * 40, "2" * 40
            ),
            ("2026-07-15T12:00:00Z", "2026-07-15T12:00:01Z"),
        )
        for aliased_epoch in (True, 1.0):
            with self.subTest(aliased_epoch=aliased_epoch):
                mutated = dict(document)
                mutated["epoch"] = aliased_epoch
                with self.assertRaises(module.VerificationError):
                    module._validate_evidence_common(
                        mutated, "CH-T001-E01", "1" * 40, "2" * 40
                    )
        self.assertTrue(
            module._strict_equal(
                {"bytes": 1, "nested": [False, {"rows": 2}]},
                {"bytes": 1, "nested": [False, {"rows": 2}]},
            )
        )
        for observed, expected in (
            (True, 1),
            (1.0, 1),
            ({"bytes": 1.0}, {"bytes": 1}),
            ({"nested": [0]}, {"nested": [False]}),
        ):
            with self.subTest(observed=observed, expected=expected):
                self.assertFalse(module._strict_equal(observed, expected))
        self.assertEqual(len(module.EVIDENCE_SCHEMA_IDS), 9)
        self.assertEqual(len(module.REVIEW_LOGICAL_SCHEMA_IDS), 2)
        self.assertTrue(
            all(value.endswith(".v1") for value in module.EVIDENCE_SCHEMA_IDS.values())
        )

    def test_n16_empty_placeholder_or_cross_record_evidence_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["typed_evidence"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N16", facts)
        with self.assertRaises(module.VerificationError):
            module._exact_keys({}, module.EVIDENCE_COMMON_KEYS, "EMPTY_EVIDENCE")
        with self.assertRaises(module.VerificationError):
            module._exact_keys(
                {key: "value" for key in module.EVIDENCE_COMMON_KEYS}
                | {"unknown": "key"},
                module.EVIDENCE_COMMON_KEYS,
                "UNKNOWN_EVIDENCE_KEY",
            )
        with self.assertRaises(module.VerificationError):
            module._text("TODO", "PLACEHOLDER_EVIDENCE")
        mismatched = {
            "schema_id": module.EVIDENCE_SCHEMA_IDS["CH-T001-E01"],
            "evidence_id": "CH-T001-E01",
            "task_id": "CH-T001",
            "epoch": 1,
            "freeze_commit": "1" * 40,
            "implementation_commit": "3" * 40,
            "started_at_utc": "2026-07-15T12:00:01Z",
            "completed_at_utc": "2026-07-15T12:00:00Z",
            "result": "FAIL",
        }
        with self.assertRaises(module.VerificationError):
            module._validate_evidence_common(
                mismatched, "CH-T001-E01", "1" * 40, "2" * 40
            )

    def test_n17_exact_product_hashes_are_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N17", accepted_facts()))
        self.assertEqual(
            module.EXPECTED_PRODUCT_SHA256,
            {
                module.PRODUCT_TOOL: (
                    "56b8af777db52e6c1e721bcdae92636f84c4ded8a1b3bdfbc85689d2835910d7"
                ),
                module.PRODUCT_TESTS: (
                    "75ef5ac0bcf26c5a0a391306055dd226d14e1002958a7f763aa23c2a7b589192"
                ),
            },
        )
        self.assertEqual(len(module.EXPECTED_PRODUCT_TEST_IDS), 98)
        tool = b"exact-tool-fixture\n"
        tests = b"exact-tests-fixture\n"
        expected = {
            module.PRODUCT_TOOL: hashlib.sha256(tool).hexdigest(),
            module.PRODUCT_TESTS: hashlib.sha256(tests).hexdigest(),
        }
        with mock.patch.object(module, "EXPECTED_PRODUCT_SHA256", expected):
            module._validate_product_identities(tool, tests)

    def test_n17_product_hash_substitution_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["product_hashes"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N17", facts)
        with self.assertRaises(module.VerificationError):
            module._validate_product_identities(b"wrong-tool", b"wrong-tests")

    def test_n18_create_once_absent_target_contract_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N18", accepted_facts()))
        self.assertEqual(
            module.EXPECTED_CREATE_ONCE_STATES,
            {
                "OPEN",
                "TEMP_FSYNCED",
                "RENAME_OUTCOME_UNKNOWN",
                "RENAME_REJECTED",
                "RENAMED_UNSYNCED",
                "PARENT_FSYNCED",
                "VERIFIED_SUCCESS",
            },
        )
        self.assertTrue(
            {
                "test_concurrent_creators_allow_at_most_one_success_without_clobber",
                "test_post_inventory_failure_never_unlinks_canonical_target",
                "test_restart_verifies_but_never_regenerates_existing_output",
            }.issubset(module.EXPECTED_PRODUCT_TEST_IDS)
        )
        commands = module._expected_qualification_argv("1" * 40, "2" * 40)
        generation = commands["LEDGER_GENERATE"]
        self.assertNotIn("--replace", generation)
        self.assertEqual(generation[-2:], ["--output", module.LEDGER_PATH])

    def test_n18_replacement_authority_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["create_once"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N18", facts)

    def test_n19_exact_secret_ignore_is_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N19", accepted_facts()))
        module._validate_gitignore_identity(module.EXPECTED_GITIGNORE_BYTES)
        module._validate_freeze_surface_contract(freeze_surface_fixture(module))

    def test_n19_missing_secret_ignore_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["secret_ignore"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N19", facts)
        missing = module.EXPECTED_GITIGNORE_BYTES.replace(
            b".env\n", b".environment\n", 1
        )
        with self.assertRaises(module.VerificationError):
            module._validate_gitignore_identity(missing)
        freeze = freeze_surface_fixture(module)
        freeze["claim_outcomes"][0]["public_surfaces"] = []
        with self.assertRaises(module.VerificationError):
            module._validate_freeze_surface_contract(freeze)

    def test_n20_initial_unassigned_rows_are_accepted(self):
        module = verifier_module()
        self.assertTrue(module.validate_control("CH-T001-N20", accepted_facts()))
        row = {field: "" for field in module.FIELDS}
        row.update(
            {
                "path": "pending-review.txt",
                "generated": "UNKNOWN",
                "public_surface": "UNKNOWN",
                "security_critical": "UNKNOWN",
                "science_critical": "UNKNOWN",
                "authority_critical": "UNKNOWN",
                "reviewer": "UNASSIGNED",
                "review_status": "UNREVIEWED",
                "provenance_review_status": "UNREVIEWED",
                "license_review_status": "UNREVIEWED",
            }
        )
        module._validate_initial_review_state([row])

    def test_n20_premature_assignment_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["unassigned"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_control("CH-T001-N20", facts)
        row = {field: "" for field in module.FIELDS}
        row.update(
            {
                "path": "pending-review.txt",
                "generated": "UNKNOWN",
                "public_surface": "UNKNOWN",
                "security_critical": "UNKNOWN",
                "science_critical": "UNKNOWN",
                "authority_critical": "UNKNOWN",
                "reviewer": "premature-assignment@local.invalid",
                "review_status": "UNREVIEWED",
                "provenance_review_status": "UNREVIEWED",
                "license_review_status": "UNREVIEWED",
            }
        )
        with self.assertRaises(module.VerificationError):
            module._validate_initial_review_state([row])

    def test_typed_numeric_and_text_values_fail_closed(self):
        module = verifier_module()
        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=value):
                with self.assertRaises(module.VerificationError):
                    module._number(value, "NONFINITE")
        for value in ("line\nfeed", "non\u00adcanonical"):
            with self.subTest(value=value):
                with self.assertRaises(module.VerificationError):
                    module._text(value, "CONTROL_TEXT")

    def test_activation_schemas_and_exact_safe_directory_are_frozen(self):
        module = verifier_module()
        self.assertEqual(len(module.ACTIVATION_SCHEMA_IDS), 4)
        self.assertTrue(
            all(
                value.endswith(".v1") for value in module.ACTIVATION_SCHEMA_IDS.values()
            )
        )
        environment = module._environment(Path("/repo"))
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "5")
        self.assertEqual(environment["GIT_CONFIG_KEY_4"], "safe.directory")
        self.assertEqual(environment["GIT_CONFIG_VALUE_4"], "/repo")
        commands = module._expected_qualification_argv("1" * 40, "2" * 40)
        for phase, argv in commands.items():
            with self.subTest(phase=phase):
                python_index = argv.index(module.EVIDENCE_PYTHON)
                self.assertEqual(
                    argv[python_index : python_index + 4],
                    [module.EVIDENCE_PYTHON, "-B", "-I", "-P"],
                )
                self.assertNotIn("--replace", argv)

    def test_activation_command_chronology_is_fail_closed(self):
        module = verifier_module()

        def command(started, completed):
            stdout = "pass\n"
            stderr = ""
            return {
                "argv": ["/usr/bin/true"],
                "completed_at_utc": completed,
                "cwd": ".",
                "exit_code": 0,
                "id": "CH-T001-A01-CMD01",
                "phase": "TEST",
                "started_at_utc": started,
                "stderr": stderr,
                "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                "stdout": stdout,
                "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            }

        valid = command("2026-07-15T12:00:02Z", "2026-07-15T12:00:03Z")
        self.assertEqual(
            module._validate_activation_command(
                valid,
                command_id="CH-T001-A01-CMD01",
                phase="TEST",
                argv=["/usr/bin/true"],
                outer_started="2026-07-15T12:00:00Z",
                outer_completed="2026-07-15T12:00:04Z",
                previous_completed="2026-07-15T12:00:01Z",
            ),
            valid,
        )
        with self.assertRaises(module.VerificationError):
            module._validate_activation_command(
                valid,
                command_id="CH-T001-A01-CMD01",
                phase="TEST",
                argv=["/usr/bin/true"],
                outer_started="2026-07-15T12:00:00Z",
                outer_completed="2026-07-15T12:00:04Z",
                previous_completed="2026-07-15T12:00:03Z",
            )

    def test_retained_ci_records_and_logs_are_byte_bound(self):
        module = verifier_module()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for name in module.CI_JOB_NAMES:
                archive.writestr(f"0_{name}.txt", f"job {name} completed\n")
        payload = stream.getvalue()
        module._validate_ci_log_archive(payload)
        record = {
            "bytes": len(payload),
            "capture_argv": [
                module.GH_EXECUTABLE,
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "-H",
                f"Accept: {module.GH_ACCEPT_HEADER}",
                "-H",
                f"X-GitHub-Api-Version: {module.GH_API_VERSION}",
                "example/logs",
            ],
            "completed_at_utc": "2026-07-15T12:00:02Z",
            "content_base64": base64.b64encode(payload).decode("ascii"),
            "exit_code": 0,
            "kind": "ATTEMPT_LOG_ARCHIVE_ZIP",
            "media_type": "application/zip",
            "request_headers": [
                f"Accept: {module.GH_ACCEPT_HEADER}",
                f"X-GitHub-Api-Version: {module.GH_API_VERSION}",
            ],
            "sha256": hashlib.sha256(payload).hexdigest(),
            "source_url": "https://api.github.com/example/logs",
            "started_at_utc": "2026-07-15T12:00:01Z",
            "stderr": "",
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "tool_version": module.GH_VERSION,
        }
        self.assertEqual(
            module._retained_ci_payload(
                record,
                kind="ATTEMPT_LOG_ARCHIVE_ZIP",
                source_url="https://api.github.com/example/logs",
                api_path="example/logs",
                media_type="application/zip",
                maximum=module.MAX_CI_LOG_ARCHIVE_BYTES,
                outer_started="2026-07-15T12:00:00Z",
                outer_completed="2026-07-15T12:00:03Z",
                previous_completed="2026-07-15T12:00:00Z",
            ),
            (payload, "2026-07-15T12:00:02Z"),
        )
        record["sha256"] = "0" * 64
        with self.assertRaises(module.VerificationError):
            module._retained_ci_payload(
                record,
                kind="ATTEMPT_LOG_ARCHIVE_ZIP",
                source_url="https://api.github.com/example/logs",
                api_path="example/logs",
                media_type="application/zip",
                maximum=module.MAX_CI_LOG_ARCHIVE_BYTES,
                outer_started="2026-07-15T12:00:00Z",
                outer_completed="2026-07-15T12:00:03Z",
                previous_completed="2026-07-15T12:00:00Z",
            )
        misleading = io.BytesIO()
        with zipfile.ZipFile(misleading, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "0_build-test.txt",
                "\n".join(module.CI_JOB_NAMES) + "\n",
            )
        with self.assertRaises(module.VerificationError):
            module._validate_ci_log_archive(misleading.getvalue())

    def test_resource_timing_stream_rejects_contradictory_records(self):
        module = verifier_module()
        stderr = "0.10 real 0.05 user 0.01 sys\n1234 maximum resident set size\n"
        command = {"stderr": stderr}
        self.assertEqual(module._resource_real_seconds(command), 0.1)
        self.assertEqual(module._resource_peak_rss_bytes(command), 1234)
        command["stderr"] += "0.20 real 0.10 user 0.02 sys\n"
        with self.assertRaises(module.VerificationError):
            module._resource_real_seconds(command)

    def test_resource_distribution_values_fail_closed(self):
        module = verifier_module()
        with self.assertRaises(module.VerificationError):
            module._number_list(
                [0.1, 0.2, True, 0.4, 0.5],
                "BOOLEAN_RESOURCE_SAMPLE",
                exact_length=module.RESOURCE_SAMPLE_COUNT,
            )
        with self.assertRaises(module.VerificationError):
            module._number_list(
                [0.1, 0.2, float("nan"), 0.4, 0.5],
                "NONFINITE_RESOURCE_SAMPLE",
                exact_length=module.RESOURCE_SAMPLE_COUNT,
            )
        with self.assertRaises(module.VerificationError):
            module._integer_list(
                [1024, 2048, False, 4096, 8192],
                "BOOLEAN_RSS_SAMPLE",
                exact_length=module.RESOURCE_SAMPLE_COUNT,
                minimum=1,
            )
        with self.assertRaises(module.VerificationError):
            module._number_list(
                [0.1] * (module.RESOURCE_SAMPLE_COUNT - 1),
                "SHORT_RESOURCE_DISTRIBUTION",
                exact_length=module.RESOURCE_SAMPLE_COUNT,
            )

    def test_mutable_review_fields_match_product_fail_closed_rules(self):
        module = verifier_module()
        row = {field: "" for field in module.FIELDS}
        row.update(
            {
                "path": "reviewed.txt",
                "generated": "UNKNOWN",
                "public_surface": "UNKNOWN",
                "security_critical": "UNKNOWN",
                "science_critical": "UNKNOWN",
                "authority_critical": "UNKNOWN",
                "reviewer": "UNASSIGNED",
                "review_status": "UNREVIEWED",
                "provenance_review_status": "UNREVIEWED",
                "license_review_status": "UNREVIEWED",
            }
        )
        module._validate_mutable(row, {row["path"]})
        unresolved_generator = dict(row)
        unresolved_generator["generator"] = "tools/unproven-generator.py"
        with self.assertRaises(module.VerificationError):
            module._validate_mutable(unresolved_generator, {row["path"]})
        in_review = dict(
            row,
            reviewer="registered-reviewer@local.invalid",
            review_status="IN_REVIEW",
            disposition="PRELIMINARY_FINDING_RETAINED",
        )
        module._validate_mutable(in_review, {row["path"]})
        gitignore = dict(row, path=module.GITIGNORE_PATH, public_surface="NO")
        with self.assertRaises(module.VerificationError):
            module._validate_mutable(gitignore, {gitignore["path"]})
        product_tool = dict(row, path=module.PRODUCT_TOOL, public_surface="YES")
        with self.assertRaises(module.VerificationError):
            module._validate_mutable(product_tool, {product_tool["path"]})
        completed = dict(row)
        completed.update(
            {
                "generated": "NO",
                "language": "Plain Text",
                "format": "TEXT_UTF8",
                "public_surface": "NO",
                "security_critical": "NO",
                "science_critical": "NO",
                "authority_critical": "NO",
                "reviewer": "registered-reviewer@local.invalid",
                "review_status": "REVIEWED",
                "provenance_review_status": "NOT_APPLICABLE",
                "license_review_status": "NOT_APPLICABLE",
                "defects": "RECORDED_DEFECT: follow-up retained",
                "disposition": "ACCEPTED",
                "completed_at": "2026-07-15T12:00:00Z",
            }
        )
        module._validate_mutable(completed, {completed["path"]})
        adverse = dict(completed)
        adverse["disposition"] = "REJECTED"
        with self.assertRaises(module.VerificationError):
            module._validate_mutable(adverse, {adverse["path"]})
        for field, value in (
            ("reviewer", " none "),
            ("reviewer", "unknown"),
            ("completed_at", "2026-02-30T12:00:00Z"),
            ("completed_at", "2026-07-15T12:00:00Z"),
        ):
            with self.subTest(field=field, value=value):
                mutated = dict(row)
                mutated[field] = value
                with self.assertRaises(module.VerificationError):
                    module._validate_mutable(mutated, {row["path"]})

    def test_generated_evolution_freezes_rules_and_requires_reviewed_resolution(self):
        module = verifier_module()
        frozen_yes = {
            "path": "Cargo.lock",
            "generated": "YES",
            "generator": "PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS",
        }
        module._validate_generated_evolution(dict(frozen_yes), frozen_yes)
        changed_yes = dict(frozen_yes, generated="NO", generator="")
        with self.assertRaises(module.VerificationError):
            module._validate_generated_evolution(changed_yes, frozen_yes)

        frozen_unknown = {
            "path": "README.md",
            "generated": "UNKNOWN",
            "generator": "",
        }
        unresolved = {
            **frozen_unknown,
            "review_status": "UNREVIEWED",
            "reviewer": "UNASSIGNED",
            "completed_at": "",
            "disposition": "",
            "provenance_review_status": "UNREVIEWED",
            "provenance_evidence": "",
        }
        module._validate_generated_evolution(unresolved, frozen_unknown)
        premature = dict(unresolved, generated="NO")
        with self.assertRaises(module.VerificationError):
            module._validate_generated_evolution(premature, frozen_unknown)
        reviewed = dict(
            premature,
            review_status="REVIEWED",
            reviewer="registered-reviewer@local.invalid",
            completed_at="2026-07-15T12:00:00Z",
            disposition="ACCEPTED",
            provenance_review_status="CONFIRMED",
            provenance_evidence="exact source reconstruction",
        )
        module._validate_generated_evolution(reviewed, frozen_unknown)

    def test_ledger_parser_enforces_field_limits_unicode_nfc_and_no_controls(self):
        module = verifier_module()
        path_index = module.FIELDS.index("path")
        generated_index = module.FIELDS.index("generated")
        defects_index = module.FIELDS.index("defects")

        def render(*, field_index=None, value=""):
            records = [list(module.FIELDS)]
            for index in range(module.EXPECTED_IMPLEMENTATION_PATHS):
                row = [""] * len(module.FIELDS)
                row[path_index] = f"p/{index:03d}.txt"
                if index == 0 and field_index is not None:
                    row[field_index] = value
                records.append(row)
            stream = io.StringIO(newline="")
            module.csv.writer(stream, lineterminator="\n").writerows(records)
            return stream.getvalue().encode("utf-8")

        self.assertEqual(len(module._parse_ledger(render())), 352)
        for field_index, value in (
            (generated_index, "x" * (module.MAX_ENUM_CELL_BYTES + 1)),
            (defects_index, "e\u0301"),
            (defects_index, "line\nfeed"),
        ):
            with self.subTest(field_index=field_index, value_length=len(value)):
                with self.assertRaises(module.VerificationError):
                    module._parse_ledger(render(field_index=field_index, value=value))

    def test_cf01_consistent_syntax_and_semantics_are_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF01", accepted_facts())
        )

    def test_cf01_valid_csv_with_contradictory_semantics_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["capture_binding"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF01", facts)

    def test_cf02_frozen_authorized_chain_is_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF02", accepted_facts())
        )

    def test_cf02_unauthorized_producer_substitution_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["output_binding"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF02", facts)

    def test_cf03_current_retained_inventory_is_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF03", accepted_facts())
        )

    def test_cf03_stale_retained_inventory_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["retention"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF03", facts)

    def test_cf04_matching_contract_digests_are_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF04", accepted_facts())
        )

    def test_cf04_correct_version_with_wrong_digest_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["digests"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF04", facts)

    def test_cf05_exact_repository_distribution_is_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF05", accepted_facts())
        )

    def test_cf05_clean_nonrepresentative_subset_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["paths_equal"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF05", facts)

    def test_cf06_bounded_success_without_fallback_is_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF06", accepted_facts())
        )

    def test_cf06_timeout_followed_by_fallback_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["bounded"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF06", facts)

    def test_cf07_exact_regular_inventory_modes_are_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF07", accepted_facts())
        )

    def test_cf07_privileged_or_experimental_extra_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["zero_extras"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF07", facts)

    def test_cf08_complete_schema_migration_is_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF08", accepted_facts())
        )

    def test_cf08_partial_defaulted_schema_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["canonical"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF08", facts)

    def test_cf09_durable_self_and_retention_binding_is_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF09", accepted_facts())
        )

    def test_cf09_missing_durable_ledger_output_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["self_binding"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF09", facts)

    def test_cf10_canonical_odd_path_handling_is_accepted(self):
        module = verifier_module()
        self.assertTrue(
            module.validate_counterfactual("CH-T001-CF10", accepted_facts())
        )

    def test_cf10_noncanonical_odd_path_is_rejected(self):
        module = verifier_module()
        facts = accepted_facts()
        facts["canonical"] = False
        with self.assertRaises(module.VerificationError):
            module.validate_counterfactual("CH-T001-CF10", facts)


if __name__ == "__main__":
    unittest.main()
