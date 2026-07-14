#!/usr/bin/env python3
"""Verify the normative Haldir 0.9 authority model without network access."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_MODEL_BYTES = 64 * 1024
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_PROFILE_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 512 * 1024
MAX_REQUIREMENTS_BYTES = 256 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_TOP_LEVEL = {
    "schema_version",
    "requirement_id",
    "release_target",
    "author",
    "normative_document",
    "claimed_profile",
    "decision_action_separation",
    "prohibited_authority_expansion",
    "claim_scope",
    "evidence_sources",
}
EXPECTED_PRINCIPALS = {
    "admission-authority",
    "controller-a",
    "controller-b",
    "gate",
    "lifecycle",
    "mission-authority",
    "observer",
    "robot-crebain",
}
EXPECTED_NON_GATE = sorted(EXPECTED_PRINCIPALS - {"gate"})
EXPECTED_CONJUNCTION = [
    "gate_active_and_not_fault_latched",
    "bounded_canonical_authenticated_controller_intent",
    "route_session_lease_admission_and_trusted_state_match",
    "deterministic_policy_allow_with_useful_validity",
    "authorization_revision_unchanged",
    "acl_exclusive_publication_authority_current",
    "new_gate_owned_output_position",
    "fresh_gate_owned_frame_built_and_exactly_validated",
    "opaque_publication_transition_binds_route_bytes_and_digest",
]
EXPECTED_PROHIBITIONS = [
    "controller_intent_is_not_plant_command",
    "serialization_is_not_authorization",
    "controller_bytes_are_not_forwarded",
    "advisory_evidence_cannot_grant_or_widen_authority",
    "consumer_receipt_cannot_retroactively_grant_authority",
    "failed_or_missing_conjunct_has_no_fallback",
]
EXPECTED_LENSES = {
    "correctness_and_invariants",
    "safety_and_failure_behavior",
    "security_and_adversarial_behavior",
    "determinism_and_reproducibility",
    "performance_and_bounded_resources",
    "api_schema_and_compatibility",
    "observability_and_provenance",
    "testing_and_independent_evidence",
    "documentation_and_operator_usability",
    "ecosystem_composition_and_governance",
}


class AuthorityModelError(ValueError):
    """The authority model or one of its evidence inputs is invalid."""


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
    except OSError as error:
        raise AuthorityModelError(f"AUTHORITY_READ_FAILED:{label}") from error
    if len(payload) > limit:
        raise AuthorityModelError(f"AUTHORITY_RESOURCE_BOUND:{label}")
    return payload


def _load_json(path: Path, limit: int, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_read_bounded(path, limit, label))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorityModelError(f"AUTHORITY_JSON_INVALID:{label}") from error
    if not isinstance(value, dict):
        raise AuthorityModelError(f"AUTHORITY_JSON_NOT_OBJECT:{label}")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AuthorityModelError(f"AUTHORITY_INVALID_HEX:{label}")
    return value


def _rust_block(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise AuthorityModelError(f"AUTHORITY_RUST_MARKER_MISSING:{marker}")
    opening = source.find("{", start)
    if opening < 0:
        raise AuthorityModelError(f"AUTHORITY_RUST_BLOCK_INVALID:{marker}")
    depth = 0
    for offset, character in enumerate(source[opening:], start=opening):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : offset]
    raise AuthorityModelError(f"AUTHORITY_RUST_BLOCK_UNTERMINATED:{marker}")


def _verify_document(model: dict[str, Any], repo: Path) -> None:
    record = model.get("normative_document")
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise AuthorityModelError("AUTHORITY_DOCUMENT_RECORD_INVALID")
    if record.get("path") != "docs/release/0.9.0/AUTHORITY-CONTRACT.md":
        raise AuthorityModelError("AUTHORITY_DOCUMENT_PATH_INVALID")
    expected = _require_hex(record.get("sha256"), HEX64, "normative_document.sha256")
    payload = _read_bounded(repo / record["path"], MAX_DOCUMENT_BYTES, "normative_document")
    if _sha256(payload) != expected:
        raise AuthorityModelError("AUTHORITY_DOCUMENT_DIGEST_MISMATCH")
    try:
        document = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuthorityModelError("AUTHORITY_DOCUMENT_UTF8_INVALID") from error
    required_fragments = (
        "## HALDIR-0.9-T001 — sole plant-command principal",
        "**SHALL** be the sole Haldir principal",
        "*unauthorized plant command*",
        "**SHALL NOT** create,",
        "`ALLOW(HOLD)` **SHALL** create",
        "`DENY` and `ERROR` **SHALL NOT** create",
        "enforcement hardening remains partial",
        "complete mediation",
        "**NOT_CLAIMED**",
    )
    if any(fragment not in document for fragment in required_fragments):
        raise AuthorityModelError("AUTHORITY_DOCUMENT_NORMATIVE_FRAGMENT_MISSING")
    claim_ledger = _read_bounded(
        repo / "docs/CLAIM-LEDGER.md", MAX_EVIDENCE_BYTES, "claim_ledger"
    ).decode("utf-8")
    if claim_ledger.count("| CL-AUTHORITY-MODEL-01 |") != 1 or not all(
        fragment in claim_ledger
        for fragment in (
            "implementation enforcement as PARTIAL",
            "not sealed lower APIs",
            "complete mediation",
        )
    ):
        raise AuthorityModelError("AUTHORITY_CLAIM_LEDGER_ENTRY_INVALID")


def _verify_model_contract(model: dict[str, Any]) -> None:
    if set(model) != EXPECTED_TOP_LEVEL:
        raise AuthorityModelError("AUTHORITY_MODEL_TOP_LEVEL_INVALID")
    if (
        model.get("schema_version") != "1.0.0"
        or model.get("requirement_id") != "HALDIR-0.9-T001"
        or model.get("release_target") != "0.9.0"
        or model.get("author") != {"name": "Sepehr Mahmoudian"}
    ):
        raise AuthorityModelError("AUTHORITY_MODEL_IDENTITY_INVALID")

    profile = model.get("claimed_profile")
    if not isinstance(profile, dict):
        raise AuthorityModelError("AUTHORITY_CLAIMED_PROFILE_INVALID")
    expected_profile_fields = {
        "profile_id",
        "compatibility",
        "protected_route_name",
        "protected_route",
        "plant_command_definition",
        "command_shaped_data_is_authority",
        "unauthorized_final_route_frame_is_plant_command",
        "sole_haldir_principal",
        "authority_conjunction",
        "non_gate_principals",
    }
    if set(profile) != expected_profile_fields:
        raise AuthorityModelError("AUTHORITY_CLAIMED_PROFILE_FIELDS_INVALID")
    if (
        profile.get("profile_id") != "haldir-secure-reference-v1"
        or profile.get("compatibility") != "PRE_AUTHORITY_ACL_ONLY"
        or profile.get("protected_route_name") != "final_command"
        or profile.get("protected_route") != "haldir-ncp/session/uav-1/command"
        or profile.get("plant_command_definition")
        != "exact_frame_intended_for_plant_consumption_on_protected_final_route"
        or profile.get("command_shaped_data_is_authority") is not False
        or profile.get("unauthorized_final_route_frame_is_plant_command") is not True
        or profile.get("authority_conjunction") != EXPECTED_CONJUNCTION
        or profile.get("non_gate_principals") != EXPECTED_NON_GATE
    ):
        raise AuthorityModelError("AUTHORITY_CLAIMED_PROFILE_SEMANTICS_INVALID")
    if profile.get("sole_haldir_principal") != {
        "principal_id": "gate",
        "role": "gate",
        "certificate_common_name": "haldir-gate.secure-reference-v1",
        "application_key_role": "GATE_APPLICATION",
    }:
        raise AuthorityModelError("AUTHORITY_SOLE_PRINCIPAL_INVALID")

    separation = model.get("decision_action_separation")
    if separation != {
        "decision_outcomes": ["ALLOW", "DENY", "ERROR"],
        "plant_actions": ["HOLD", "VELOCITY_LOCAL_NED"],
        "allow_hold": "creates_bounded_zero_velocity_plant_command",
        "deny_or_error": "creates_no_plant_command",
        "decision_named_hold_or_estop": False,
        "haldir_originated_estop": "NOT_CLAIMED",
    }:
        raise AuthorityModelError("AUTHORITY_DECISION_ACTION_CONFLATION")
    if model.get("prohibited_authority_expansion") != EXPECTED_PROHIBITIONS:
        raise AuthorityModelError("AUTHORITY_PROHIBITIONS_INVALID")
    if model.get("claim_scope") != {
        "normative_authority_rule": "FROZEN",
        "implementation_enforcement": "PARTIAL",
        "complete_mediation": "NOT_CLAIMED",
        "delivery": "NOT_CLAIMED",
        "plant_acceptance": "NOT_CLAIMED",
        "plant_application": "NOT_CLAIMED",
        "physical_system_safety": "NOT_CLAIMED",
        "production_deployment_security": "NOT_CLAIMED",
        "other_deployment_modes": "DEFERRED_TO_HALDIR-0.9-T005",
    }:
        raise AuthorityModelError("AUTHORITY_CLAIM_SCOPE_INVALID")


def _verify_profile(model: dict[str, Any], profile_path: Path) -> None:
    deployment = _load_json(profile_path, MAX_PROFILE_BYTES, "deployment_profile")
    claimed = model["claimed_profile"]
    if deployment.get("profile_id") != claimed["profile_id"]:
        raise AuthorityModelError("AUTHORITY_PROFILE_ID_MISMATCH")
    routes = deployment.get("routes")
    if not isinstance(routes, dict) or routes.get("final_command") != claimed["protected_route"]:
        raise AuthorityModelError("AUTHORITY_PROFILE_ROUTE_MISMATCH")
    principals = deployment.get("principals")
    if not isinstance(principals, dict) or set(principals) != EXPECTED_PRINCIPALS:
        raise AuthorityModelError("AUTHORITY_PROFILE_PRINCIPALS_INVALID")

    final_publishers: list[str] = []
    for principal_id, principal in principals.items():
        if not isinstance(principal, dict) or not isinstance(principal.get("publish"), list):
            raise AuthorityModelError("AUTHORITY_PROFILE_PRINCIPAL_INVALID")
        if "final_command" in principal["publish"]:
            final_publishers.append(principal_id)
    if final_publishers != ["gate"]:
        raise AuthorityModelError("AUTHORITY_PROFILE_FINAL_PUBLISHERS_INVALID")
    gate = principals["gate"]
    if gate.get("role") != "gate" or gate.get("certificate_common_name") != (
        "haldir-gate.secure-reference-v1"
    ):
        raise AuthorityModelError("AUTHORITY_PROFILE_GATE_IDENTITY_INVALID")
    for receiver in ("observer", "robot-crebain"):
        subscriptions = principals[receiver].get("subscribe")
        if not isinstance(subscriptions, list) or "final_command" not in subscriptions:
            raise AuthorityModelError("AUTHORITY_PROFILE_FINAL_RECEIVER_INVALID")


def _attempt_index(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    attempts = result.get("attempts")
    if not isinstance(attempts, list):
        raise AuthorityModelError("AUTHORITY_EVIDENCE_ATTEMPTS_INVALID")
    indexed: dict[str, dict[str, Any]] = {}
    for attempt in attempts:
        if not isinstance(attempt, dict) or not isinstance(attempt.get("case_id"), str):
            raise AuthorityModelError("AUTHORITY_EVIDENCE_ATTEMPT_INVALID")
        case_id = attempt["case_id"]
        if case_id in indexed:
            raise AuthorityModelError("AUTHORITY_EVIDENCE_CASE_DUPLICATE")
        indexed[case_id] = attempt
    return indexed


def _verify_live_evidence(model: dict[str, Any], result_path: Path) -> None:
    result = _load_json(result_path, MAX_EVIDENCE_BYTES, "retained_live_acl_result")
    if (
        result.get("status") != "pass"
        or result.get("callback_overflow") is not False
        or result.get("no_certificate_rejected") is not True
    ):
        raise AuthorityModelError("AUTHORITY_EVIDENCE_RESULT_INVALID")
    indexed = _attempt_index(result)
    route = model["claimed_profile"]["protected_route"]
    sources = model["evidence_sources"]
    positive_cases = sources.get("expected_gate_positive_cases")
    denial_cases = sources.get("expected_non_gate_denial_cases")
    expected_denials = [f"final-denied-{principal}" for principal in EXPECTED_NON_GATE]
    if positive_cases != ["final-positive-pre", "final-positive-post"]:
        raise AuthorityModelError("AUTHORITY_EVIDENCE_POSITIVE_SET_INVALID")
    if denial_cases != expected_denials:
        raise AuthorityModelError("AUTHORITY_EVIDENCE_DENIAL_SET_INVALID")

    for case_id in positive_cases:
        attempt = indexed.get(case_id)
        if (
            attempt is None
            or attempt.get("sender") != "gate"
            or attempt.get("operation") != "put"
            or attempt.get("route") != route
            or attempt.get("local_put_ok") is not True
            or set(attempt.get("expected_receivers", [])) != {"observer", "robot-crebain"}
        ):
            raise AuthorityModelError("AUTHORITY_EVIDENCE_GATE_POSITIVE_INVALID")
    denied_ids = result.get("denied_case_ids")
    if not isinstance(denied_ids, list) or not set(denial_cases).issubset(denied_ids):
        raise AuthorityModelError("AUTHORITY_EVIDENCE_DENIED_INDEX_INVALID")
    for principal, case_id in zip(EXPECTED_NON_GATE, denial_cases, strict=True):
        attempt = indexed.get(case_id)
        if (
            attempt is None
            or attempt.get("sender") != principal
            or attempt.get("operation") != "put"
            or attempt.get("route") != route
            or attempt.get("local_put_ok") is not True
            or attempt.get("expected_receivers") != []
        ):
            raise AuthorityModelError("AUTHORITY_EVIDENCE_NON_GATE_DENIAL_INVALID")

    observations = result.get("observations")
    if not isinstance(observations, list):
        raise AuthorityModelError("AUTHORITY_EVIDENCE_OBSERVATIONS_INVALID")
    observed: dict[str, set[str]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            raise AuthorityModelError("AUTHORITY_EVIDENCE_OBSERVATION_INVALID")
        case_id = observation.get("case_id")
        receiver = observation.get("receiver")
        if isinstance(case_id, str) and isinstance(receiver, str):
            observed.setdefault(case_id, set()).add(receiver)
    if any(case_id in observed for case_id in denial_cases):
        raise AuthorityModelError("AUTHORITY_EVIDENCE_DENIED_DELIVERED")
    if any(observed.get(case_id) != {"observer", "robot-crebain"} for case_id in positive_cases):
        raise AuthorityModelError("AUTHORITY_EVIDENCE_POSITIVE_OBSERVATIONS_INVALID")


def _verify_rust_contracts(model: dict[str, Any], repo: Path) -> None:
    sources = model.get("evidence_sources")
    expected_source_fields = {
        "deployment_profile",
        "retained_live_acl_result",
        "decision_contract",
        "action_contract",
        "publication_authority_contract",
        "key_role_contract",
        "gate_decision_pipeline",
        "runtime_semantics_tests",
        "expected_gate_positive_cases",
        "expected_non_gate_denial_cases",
    }
    if not isinstance(sources, dict) or set(sources) != expected_source_fields:
        raise AuthorityModelError("AUTHORITY_EVIDENCE_SOURCES_INVALID")
    expected_paths = {
        "deployment_profile": "deploy/secure-reference-v1/profile.json",
        "retained_live_acl_result": "evidence/11-secure-zenoh-live/result.json",
        "decision_contract": "crates/haldir-contracts/src/receipt.rs",
        "action_contract": "crates/haldir-contracts/src/action.rs",
        "publication_authority_contract": "crates/haldir-contracts/src/status.rs",
        "key_role_contract": "crates/haldir-crypto/src/role.rs",
        "gate_decision_pipeline": "crates/haldir-gate/src/actor.rs",
        "runtime_semantics_tests": "crates/haldir-gate/src/lib.rs",
    }
    if any(sources.get(name) != path for name, path in expected_paths.items()):
        raise AuthorityModelError("AUTHORITY_EVIDENCE_SOURCE_PATH_INVALID")

    decision_source = _read_bounded(
        repo / sources["decision_contract"], MAX_PROFILE_BYTES, "decision_contract"
    ).decode("utf-8")
    decision_block = _rust_block(decision_source, "pub enum DecisionOutcomeV1")
    outcomes = re.findall(r'^\s*\w+\s*=\s*\d+\s*=>\s*"([A-Z_]+)"', decision_block, re.MULTILINE)
    if outcomes != model["decision_action_separation"]["decision_outcomes"]:
        raise AuthorityModelError("AUTHORITY_RUST_DECISION_DRIFT")

    action_source = _read_bounded(
        repo / sources["action_contract"], MAX_PROFILE_BYTES, "action_contract"
    ).decode("utf-8")
    action_block = _rust_block(action_source, "pub enum RequestedActionV1")
    actions = re.findall(r"^\s{4}([A-Z][A-Za-z0-9]+)\s*\{", action_block, re.MULTILINE)
    normalized_actions = [re.sub(r"(?<!^)(?=[A-Z])", "_", action).upper() for action in actions]
    if normalized_actions != model["decision_action_separation"]["plant_actions"]:
        raise AuthorityModelError("AUTHORITY_RUST_ACTION_DRIFT")

    status_source = _read_bounded(
        repo / sources["publication_authority_contract"],
        MAX_PROFILE_BYTES,
        "publication_authority_contract",
    ).decode("utf-8")
    authorization_block = _rust_block(status_source, "authorizes_acl_only_publication")
    if "matches!(self, Self::AclExclusiveV1(_))" not in authorization_block:
        raise AuthorityModelError("AUTHORITY_RUST_PUBLICATION_STATE_DRIFT")

    role_source = _read_bounded(
        repo / sources["key_role_contract"], MAX_PROFILE_BYTES, "key_role_contract"
    ).decode("utf-8")
    if 'Self::GateApplication => "GATE_APPLICATION"' not in role_source:
        raise AuthorityModelError("AUTHORITY_RUST_GATE_ROLE_DRIFT")

    actor_source = _read_bounded(
        repo / sources["gate_decision_pipeline"], MAX_EVIDENCE_BYTES, "gate_decision_pipeline"
    ).decode("utf-8")
    pipeline = _rust_block(actor_source, "fn decide_intent_inner")
    ordered_markers = (
        "let decision = decide(&PolicyInput",
        "let effective_validity_ms = match decision.effective_validity_ms()",
        "if self.revision.get() != captured_rev",
        "if !self.publication.authorizes_acl_only_publication()",
        "let out_seq = match self.output_stream.allocate()",
        "let build_input = GateCommandBuildInputV1",
        "action: intent.action",
        "let frame = match self.adapter.build_command(&build_input)",
        ".validate_exact_command(&frame, &build_input)",
        "receipt.decision = DecisionOutcomeV1::Allow",
    )
    positions = [pipeline.find(marker) for marker in ordered_markers]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AuthorityModelError("AUTHORITY_RUST_GATE_PIPELINE_DRIFT")

    runtime_tests = _read_bounded(
        repo / sources["runtime_semantics_tests"], MAX_LOG_BYTES, "runtime_semantics_tests"
    ).decode("utf-8")
    semantic_test = _rust_block(
        runtime_tests,
        "fn authority_contract_separates_hold_action_from_negative_decisions",
    )
    if any(
        fragment not in semantic_test
        for fragment in (
            "DecisionOutcomeV1::Allow",
            "PlantAction::Hold",
            "command.action.velocity(), [0, 0, 0]",
            "DecisionOutcomeV1::Deny",
            "DecisionOutcomeV1::Error",
            "!denied.has_prepared_publication()",
            "!errored.has_prepared_publication()",
        )
    ):
        raise AuthorityModelError("AUTHORITY_RUST_RUNTIME_SEMANTICS_TEST_DRIFT")


def _read_bounded_gzip(path: Path) -> bytes:
    try:
        with gzip.open(path, "rb") as handle:
            payload = handle.read(MAX_LOG_BYTES + 1)
    except (OSError, EOFError) as error:
        raise AuthorityModelError("AUTHORITY_VERIFICATION_LOG_INVALID") from error
    if len(payload) > MAX_LOG_BYTES:
        raise AuthorityModelError("AUTHORITY_VERIFICATION_LOG_RESOURCE_BOUND")
    return payload


def _git(repo: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise AuthorityModelError("AUTHORITY_GIT_LOOKUP_FAILED") from error
    if len(result.stdout) > MAX_LOG_BYTES:
        raise AuthorityModelError("AUTHORITY_GIT_OUTPUT_BOUND")
    return result.stdout


def _verify_log(repo: Path, record: Any, commit: str, marker: bytes) -> None:
    if not isinstance(record, dict) or set(record) != {
        "path",
        "compression",
        "gzip_timestamp",
        "uncompressed_sha256",
        "uncompressed_bytes",
        "uncompressed_lines",
    }:
        raise AuthorityModelError("AUTHORITY_VERIFICATION_LOG_RECORD_INVALID")
    if record.get("compression") != "gzip" or record.get("gzip_timestamp") != 0:
        raise AuthorityModelError("AUTHORITY_VERIFICATION_LOG_COMPRESSION_INVALID")
    payload = _read_bounded_gzip(repo / record["path"])
    if len(payload) != record["uncompressed_bytes"] or len(payload.splitlines()) != record[
        "uncompressed_lines"
    ]:
        raise AuthorityModelError("AUTHORITY_VERIFICATION_LOG_SIZE_MISMATCH")
    expected = _require_hex(record["uncompressed_sha256"], HEX64, "verification.log.sha256")
    if _sha256(payload) != expected:
        raise AuthorityModelError("AUTHORITY_VERIFICATION_LOG_DIGEST_MISMATCH")
    if commit.encode("ascii") not in payload or marker not in payload:
        raise AuthorityModelError("AUTHORITY_VERIFICATION_LOG_MARKER_MISSING")


def _verify_task_closure(repo: Path, task: dict[str, Any]) -> None:
    record = _load_json(
        repo / "release/0.9.0/evidence/t001-verification.json",
        MAX_MODEL_BYTES,
        "t001_verification",
    )
    if (
        record.get("schema_version") != "1.0.0"
        or record.get("task_id") != "T001"
        or record.get("requirement_id") != "HALDIR-0.9-T001"
        or record.get("status") != "verified"
    ):
        raise AuthorityModelError("AUTHORITY_T001_CLOSURE_IDENTITY_INVALID")
    implementation = record.get("implementation")
    if not isinstance(implementation, dict):
        raise AuthorityModelError("AUTHORITY_T001_IMPLEMENTATION_INVALID")
    commit = _require_hex(implementation.get("commit"), HEX40, "t001.commit")
    tree = _require_hex(implementation.get("tree"), HEX40, "t001.tree")
    if _git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip() != tree:
        raise AuthorityModelError("AUTHORITY_T001_TREE_MISMATCH")
    if b"gpgsig -----BEGIN SSH SIGNATURE-----" not in _git(repo, "cat-file", "commit", commit):
        raise AuthorityModelError("AUTHORITY_T001_COMMIT_UNSIGNED")
    for name, marker in (
        ("github_ci", b"verify-authority-model: OK"),
        ("github_formal", b"Model checking completed. No error has been found."),
    ):
        run = record.get(name)
        if (
            not isinstance(run, dict)
            or not isinstance(run.get("run_id"), int)
            or run["run_id"] <= 0
            or run.get("head_sha") != commit
            or run.get("conclusion") != "success"
        ):
            raise AuthorityModelError(f"AUTHORITY_T001_{name.upper()}_INVALID")
        _verify_log(repo, run.get("log"), commit, marker)
    if not any(
        isinstance(item, dict)
        and item.get("kind") == "exact_commit_verification"
        and item.get("path") == "release/0.9.0/evidence/t001-verification.json"
        and item.get("commit") == commit
        for item in task.get("evidence", [])
    ):
        raise AuthorityModelError("AUTHORITY_T001_LEDGER_CLOSURE_MISSING")


def _verify_requirements(requirements_path: Path, repo: Path) -> None:
    requirements = _load_json(requirements_path, MAX_REQUIREMENTS_BYTES, "requirements")
    tasks = requirements.get("tasks")
    if not isinstance(tasks, list):
        raise AuthorityModelError("AUTHORITY_REQUIREMENTS_TASKS_INVALID")
    by_id = {
        task.get("id"): task for task in tasks if isinstance(task, dict) and isinstance(task.get("id"), str)
    }
    t000 = by_id.get("T000")
    t001 = by_id.get("T001")
    if not isinstance(t000, dict) or t000.get("status") != "verified":
        raise AuthorityModelError("AUTHORITY_PREDECESSOR_NOT_VERIFIED")
    if (
        not isinstance(t001, dict)
        or t001.get("requirement_id") != "HALDIR-0.9-T001"
        or t001.get("dependencies") != ["T000"]
        or t001.get("status") not in {"implemented", "verified"}
    ):
        raise AuthorityModelError("AUTHORITY_REQUIREMENT_ENTRY_INVALID")
    evidence = t001.get("evidence")
    required_paths = {
        "docs/release/0.9.0/AUTHORITY-CONTRACT.md",
        "docs/CLAIM-LEDGER.md",
        "release/0.9.0/authority-model.json",
        "tools/release/verify-authority-model.py",
        "tools/release/test_verify_authority_model.py",
        "docs/release/0.9.0/MIGRATION.md",
        "crates/haldir-gate/src/lib.rs",
        "deploy/secure-reference-v1/profile.json",
        "evidence/11-secure-zenoh-live/result.json",
    }
    if not isinstance(evidence, list) or not required_paths.issubset(
        {item.get("path") for item in evidence if isinstance(item, dict)}
    ):
        raise AuthorityModelError("AUTHORITY_REQUIREMENT_EVIDENCE_INVALID")
    review = t001.get("ten_lens_review")
    if (
        not isinstance(review, dict)
        or set(review) != EXPECTED_LENSES
        or any(not isinstance(value, str) or not value.strip() for value in review.values())
    ):
        raise AuthorityModelError("AUTHORITY_REQUIREMENT_REVIEW_INVALID")
    risks = t001.get("residual_risks")
    if not isinstance(risks, list) or not risks or any(not isinstance(risk, str) for risk in risks):
        raise AuthorityModelError("AUTHORITY_REQUIREMENT_RISKS_INVALID")
    if t001["status"] == "verified":
        _verify_task_closure(repo, t001)


def verify(
    model_path: Path,
    repo: Path,
    *,
    profile_path: Path | None = None,
    result_path: Path | None = None,
    requirements_path: Path | None = None,
) -> None:
    """Verify the authority model and its repository-local evidence."""

    model = _load_json(model_path, MAX_MODEL_BYTES, "authority_model")
    _verify_model_contract(model)
    _verify_document(model, repo)
    _verify_profile(
        model,
        profile_path or repo / model["evidence_sources"]["deployment_profile"],
    )
    _verify_live_evidence(
        model,
        result_path or repo / model["evidence_sources"]["retained_live_acl_result"],
    )
    _verify_rust_contracts(model, repo)
    _verify_requirements(
        requirements_path or repo / "release/0.9.0/requirements.json",
        repo,
    )


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    model = repo / "release/0.9.0/authority-model.json"
    try:
        verify(model, repo)
    except AuthorityModelError as error:
        print(f"verify-authority-model: FAIL: {error}", file=sys.stderr)
        return 1
    print("verify-authority-model: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
