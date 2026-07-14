#!/usr/bin/env python3
"""Verify the closed Haldir 0.9 protection model without network access."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


MAX_MODEL_BYTES = 128 * 1024
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_PROFILE_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_REQUIREMENTS_BYTES = 256 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_TOP_LEVEL = {
    "schema_version",
    "requirement_id",
    "release_target",
    "author",
    "normative_document",
    "scope",
    "identity_namespaces",
    "subjects",
    "resources",
    "actions",
    "constraints",
    "time_domains",
    "trust_roots",
    "access_policy",
    "evidence_sources",
    "claim_scope",
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

EXPECTED_KEY_ROLES = [
    "GATE_APPLICATION",
    "CONTROLLER_INTENT",
    "MISSION_AUTHORITY",
    "ADMISSION_AUTHORITY",
    "POLICY_AUTHORITY",
    "REVOCATION_AUTHORITY",
    "CREBAIN_EVIDENCE",
    "DEPLOYMENT_AUTHORITY",
    "DEVELOPMENT_ONLY",
]

EXPECTED_COMPONENTS = {
    "gate_application",
    "gate_transport",
    "secure_transport_router",
    "controller",
    "mission_authority",
    "admission_authority",
    "policy_authority",
    "revocation_authority",
    "deployment_authority",
    "trusted_state_producer",
    "lifecycle_service",
    "plant_crebain",
    "observer_auditor",
    "provisioning_operator",
    "external_generation_anchor",
}

EXPECTED_STATE_RESOURCES = {
    "state:gate_application_signing_secret",
    "state:controller_intent_signing_secrets",
    "state:mission_authority_signing_secret",
    "state:admission_authority_signing_secret",
    "state:policy_authority_signing_secret",
    "state:revocation_authority_signing_secret",
    "state:deployment_authority_signing_secret",
    "state:crebain_evidence_signing_secret",
    "state:gate_transport_credentials",
    "state:controller_transport_credentials",
    "state:mission_authority_transport_credentials",
    "state:admission_authority_transport_credentials",
    "state:lifecycle_transport_credentials",
    "state:observer_transport_credentials",
    "state:plant_crebain_transport_credentials",
    "state:router_transport_trust_and_credentials",
    "state:bootstrap_application_trust",
    "state:revocation_snapshot",
    "state:deployment_package_and_artifacts",
    "state:admission_snapshot",
    "state:mission_lease_snapshot",
    "state:gate_challenge_state",
    "state:policy_snapshot",
    "state:trusted_state_snapshot",
    "state:ncp_session_identity",
    "state:gate_boot_and_output_namespace",
    "state:replay_usage_and_authorization_revision",
    "state:publication_capability_and_slot",
    "state:final_command_frame",
    "state:authenticated_durable_snapshot",
    "state:generation_anchor_head",
    "state:storage_mac_key",
    "state:evidence_journal_and_trace",
    "state:transport_profile_and_acl",
    "state:plant_application_boundary",
}

EXPECTED_OPERATIONS = [
    "authenticate_connect",
    "sign",
    "verify",
    "issue",
    "revoke",
    "configure",
    "provision",
    "submit_intent",
    "observe",
    "authorize",
    "allocate_output",
    "construct_frame",
    "validate_frame",
    "publish_once",
    "consume",
    "accept",
    "apply",
    "record_evidence",
    "recover",
    "compare_and_set_generation",
    "lifecycle_rpc",
    "enforce_acl",
    "route_transport",
]

EXPECTED_CONSTRAINTS = {
    "identity:exact_kid": "IDENTITY_CRYPTO",
    "identity:role_class_subject_key": "IDENTITY_CRYPTO",
    "identity:canonical_domain_signature": "IDENTITY_CRYPTO",
    "identity:revocation": "IDENTITY_CRYPTO",
    "scope:actual_signed_leased_route": "ROUTE_SCOPE",
    "scope:gate_boot": "ROUTE_SCOPE",
    "scope:realm_vehicle": "ROUTE_SCOPE",
    "scope:mission_phase": "ROUTE_SCOPE",
    "scope:session_pair": "ROUTE_SCOPE",
    "scope:controller_admission": "ROUTE_SCOPE",
    "scope:lease_policy": "ROUTE_SCOPE",
    "scope:source_causality": "ROUTE_SCOPE",
    "scope:controller_claims_consistency_only": "ROUTE_SCOPE",
    "ordering:typed_namespaces": "ORDERING_REPLAY",
    "ordering:intent_replay": "ORDERING_REPLAY",
    "ordering:source_advance": "ORDERING_REPLAY",
    "ordering:output_unique": "ORDERING_REPLAY",
    "ordering:ratchets": "ORDERING_REPLAY",
    "bounds:decode_ingress_collections": "BOUNDED_RESOURCES",
    "bounds:authority_intersection": "BOUNDED_RESOURCES",
    "bounds:numeric_policy": "BOUNDED_RESOURCES",
    "bounds:checked_arithmetic": "BOUNDED_RESOURCES",
    "state:active_fresh_policy_allow": "STATE_TRANSITION",
    "state:authorization_revision": "STATE_TRANSITION",
    "state:publication_and_frame": "STATE_TRANSITION",
    "state:single_opaque_publication": "STATE_TRANSITION",
    "failure:no_new_command": "FAILURE_SEMANTICS",
    "failure:no_retroactive_erasure": "FAILURE_SEMANTICS",
}

EXPECTED_TIME_DOMAINS = {
    "gate_boot_monotonic": ("AUTHORITY_CLOCK", True, False),
    "controller_local_provenance": ("PROVENANCE_CLOCK", False, False),
    "source_publisher_provenance": ("PROVENANCE_CLOCK", False, False),
    "evidence_producer_boot_monotonic": ("EVIDENCE_ORDER_CLOCK", False, False),
    "wall_clock_utc": ("AUDIT_METADATA_CLOCK", False, True),
    "opaque_boot_session_and_stream_identities": ("NOT_A_CLOCK", False, False),
    "durable_logical_ratchets": ("LOGICAL_RATCHET_NOT_A_CLOCK", False, True),
    "boot_or_epoch_scoped_logical_counters": (
        "LOGICAL_COUNTER_NOT_A_CLOCK",
        False,
        False,
    ),
}

EXPECTED_ROOT_STATUS = {
    "bootstrap_application_trust": "ACTIVE_CALLER_SUPPLIED_PREVALIDATED",
    "deployment_acceptance_policy": "IMPLEMENTED_PRIMITIVE_NOT_GATE_COMPOSED",
    "transport_mtls_router_acl": "CONFIGURATION_AND_BOUNDED_SYNTHETIC_EVIDENCE",
    "gate_application_signer": "ACTIVE_PROCESS_OWNED_PROTECTED_LOADER_UNPROVEN",
    "gate_boot_monotonic_clock": "ACTIVE_LOCAL_AUTHORITY_CLOCK",
    "configured_authority_snapshots": "ACTIVE_CALLER_SUPPLIED",
    "storage_mac_key": "IMPLEMENTED_PRIMITIVE_CALLER_SUPPLIED_SECRET",
    "external_generation_anchor": "INTERFACE_IMPLEMENTED_EXTERNAL_DEPLOYMENT_UNPROVEN",
    "local_file_generation_anchor": "DEVELOPMENT_ONLY_REWRITABLE",
    "trusted_state_provenance": "REQUIRED_EXTERNAL_ROOT_UNPROVEN",
    "plant_firmware_and_local_safe_mechanism": "EXTERNAL_ASSUMPTION_NOT_CLAIMED",
    "supply_chain_integrity_pins": "PINNED_INTEGRITY_NOT_RUNTIME_AUTHORITY",
}

EXPECTED_RULES = {
    "component:controller_intent_only",
    "component:mission_objects_only",
    "component:admission_objects_only",
    "component:policy_objects_only",
    "component:revocation_remove_only",
    "component:deployment_select_only",
    "component:gate_decision_and_construction",
    "component:gate_transport_publish_once",
    "component:router_mediate_only",
    "component:trusted_state_input_only",
    "component:lifecycle_session_only",
    "component:plant_consume_and_evidence",
    "component:observer_read_only",
    "component:operator_provision_only",
    "component:generation_anchor_ratchet_only",
}

EXPECTED_COMPONENT_BINDINGS_SHA256 = (
    "7047607ab3fb06ae9d5f613634926fb6cd399d105c903417e9a16e04429bcb37"
)
EXPECTED_APPLICATION_ROLE_BINDINGS_SHA256 = (
    "d947f7e875bec150d318a13a1710926159910693d543d0067f85867faf43324a"
)
EXPECTED_STATE_RESOURCES_SHA256 = (
    "21ed66b74b0981b951bb56e42433975e970e74dca5900fb6890c236fb51eb9db"
)
EXPECTED_ROUTE_RESOURCES_SHA256 = (
    "e17df08f4877270c6c11be0e7dcefef48b1330eecb87cb36cacde68bd50ce425"
)
EXPECTED_CONSTRAINTS_SHA256 = (
    "cf7c9b0a238dc02d6942223799bec04811c1ff6d69b608f932d1e33bafe94159"
)
EXPECTED_TIME_DOMAINS_SHA256 = (
    "288e94e09fa6c70fefddc6cd7a11fd0ff128e45c1fef02dc73ae00d2e4e881f4"
)
EXPECTED_TRUST_ROOTS_SHA256 = (
    "0accd65a4d9de3a9f0f64084a6c46e35c5c397d55f650c7652fb84f22392cdeb"
)
EXPECTED_ACCESS_POLICY_SHA256 = (
    "da2246ed4a7335a04e4faa992af6e10c0bcaca3a3b495a2baa211e64ec1ff2e4"
)
EXPECTED_ACCESS_TUPLES_SHA256 = (
    "29361a576f851a14b9d0ad3b8905473053a7350693de7d0e510f3457e0deeda0"
)

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


class ProtectionModelError(ValueError):
    """The protection model or one of its bounded evidence inputs is invalid."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtectionModelError(f"PROTECTION_JSON_DUPLICATE_KEY:{key}")
        result[key] = value
    return result


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
    except OSError as error:
        raise ProtectionModelError(f"PROTECTION_READ_FAILED:{label}") from error
    if len(payload) > limit:
        raise ProtectionModelError(f"PROTECTION_RESOURCE_BOUND:{label}")
    return payload


def _load_json(path: Path, limit: int, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_bounded(path, limit, label),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except ProtectionModelError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtectionModelError(f"PROTECTION_JSON_INVALID:{label}") from error
    if not isinstance(value, dict):
        raise ProtectionModelError(f"PROTECTION_JSON_NOT_OBJECT:{label}")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _sha256(payload)


def _records_digest(values: list[dict[str, Any]], key: str) -> str:
    return _canonical_digest(sorted(values, key=lambda item: item[key]))


def _require_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProtectionModelError(f"PROTECTION_INVALID_HEX:{label}")
    return value


def _unique_objects(values: Any, key: str, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(values, list):
        raise ProtectionModelError(f"PROTECTION_{label}_NOT_LIST")
    result: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, dict) or not isinstance(value.get(key), str):
            raise ProtectionModelError(f"PROTECTION_{label}_ENTRY_INVALID")
        identity = value[key]
        if identity in result:
            raise ProtectionModelError(f"PROTECTION_{label}_DUPLICATE:{identity}")
        result[identity] = value
    return result


def _verify_document(model: dict[str, Any], repo: Path) -> None:
    record = model.get("normative_document")
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise ProtectionModelError("PROTECTION_DOCUMENT_RECORD_INVALID")
    if record.get("path") != "docs/release/0.9.0/PROTECTION-MODEL.md":
        raise ProtectionModelError("PROTECTION_DOCUMENT_PATH_INVALID")
    expected = _require_hex(record.get("sha256"), HEX64, "normative_document.sha256")
    payload = _read_bounded(repo / record["path"], MAX_DOCUMENT_BYTES, "normative_document")
    if _sha256(payload) != expected:
        raise ProtectionModelError("PROTECTION_DOCUMENT_DIGEST_MISMATCH")
    try:
        document = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtectionModelError("PROTECTION_DOCUMENT_UTF8_INVALID") from error
    fragments = (
        "## HALDIR-0.9-T002 — protected subjects, resources, actions, constraints, time and roots",
        "The model is default-deny",
        "**SHALL NOT** gain authority by analogy",
        "identity namespaces **SHALL** remain distinct",
        "The machine model also freezes each role's allowed key class",
        "The router is an explicit non-authorizing custodian",
        "All 17 exact profile routes are protected resources",
        "Owner and custodian identifiers **SHALL** resolve",
        "No controller-declared scope",
        "contains the exact 26",
        "Gate boot-local monotonic time is the sole hot-path authorization clock",
        "`controller_t_ns` is controller-local provenance",
        "comparable across restart only within",
        "Implementation enforcement remains **PARTIAL**",
        "**NOT_CLAIMED**",
    )
    if any(fragment not in document for fragment in fragments):
        raise ProtectionModelError("PROTECTION_DOCUMENT_NORMATIVE_FRAGMENT_MISSING")

    migration = _read_bounded(
        repo / "docs/release/0.9.0/MIGRATION.md",
        MAX_DOCUMENT_BYTES,
        "migration_record",
    ).decode("utf-8")
    for requirement in ("HALDIR-0.9-T000", "HALDIR-0.9-T001", "HALDIR-0.9-T002"):
        if migration.count(f"`{requirement}`") != 1:
            raise ProtectionModelError("PROTECTION_MIGRATION_RECORD_INVALID")
    if not all(
        fragment in migration
        for fragment in (
            "No Rust API, wire, or stored-data change",
            "controller/source timestamps as provenance",
            "The release remains NO-GO",
        )
    ):
        raise ProtectionModelError("PROTECTION_MIGRATION_SEMANTICS_INVALID")

    claim_ledger = _read_bounded(
        repo / "docs/CLAIM-LEDGER.md", MAX_SOURCE_BYTES, "claim_ledger"
    ).decode("utf-8")
    if claim_ledger.count("| CL-PROTECTION-MODEL-01 |") != 1 or not all(
        fragment in claim_ledger
        for fragment in (
            "controller/source timestamps",
            "implementation enforcement as PARTIAL",
            "complete mediation",
        )
    ):
        raise ProtectionModelError("PROTECTION_CLAIM_LEDGER_ENTRY_INVALID")


def _verify_identity_and_subjects(model: dict[str, Any]) -> None:
    namespaces = _unique_objects(
        model.get("identity_namespaces"), "namespace_id", "IDENTITY_NAMESPACE"
    )
    if set(namespaces) != {
        "transport_principal",
        "certificate_common_name",
        "application_key_role",
        "logical_signed_subject",
        "component_label",
    }:
        raise ProtectionModelError("PROTECTION_IDENTITY_NAMESPACES_INVALID")
    if any(
        set(item) != {"namespace_id", "basis", "standalone_plant_command_authority"}
        or item["standalone_plant_command_authority"] is not False
        or not isinstance(item["basis"], str)
        or not item["basis"]
        for item in namespaces.values()
    ):
        raise ProtectionModelError("PROTECTION_IDENTITY_NAMESPACE_SEMANTICS_INVALID")

    subjects = model.get("subjects")
    if not isinstance(subjects, dict) or set(subjects) != {
        "transport_principals",
        "application_key_roles",
        "application_role_bindings",
        "logical_components",
        "subject_type_bindings",
    }:
        raise ProtectionModelError("PROTECTION_SUBJECTS_INVALID")
    if subjects.get("application_key_roles") != EXPECTED_KEY_ROLES:
        raise ProtectionModelError("PROTECTION_KEY_ROLES_INVALID")
    role_bindings = _unique_objects(
        subjects.get("application_role_bindings"), "role", "APPLICATION_ROLE_BINDING"
    )
    if set(role_bindings) != set(EXPECTED_KEY_ROLES):
        raise ProtectionModelError("PROTECTION_APPLICATION_ROLE_BINDING_SET_INVALID")
    role_binding_fields = {
        "role",
        "allowed_key_classes",
        "signed_objects",
        "assurance_authority",
        "implementation_status",
    }
    signed_object_fields = {
        "rust_type",
        "kind",
        "schema_major",
        "content_type",
        "external_aad",
        "subject_binding",
    }
    for role, binding in role_bindings.items():
        if (
            set(binding) != role_binding_fields
            or not isinstance(binding["allowed_key_classes"], list)
            or not binding["allowed_key_classes"]
            or len(set(binding["allowed_key_classes"]))
            != len(binding["allowed_key_classes"])
            or not set(binding["allowed_key_classes"]).issubset(
                {"ASSURANCE", "DEVELOPMENT"}
            )
            or not isinstance(binding["signed_objects"], list)
            or not isinstance(binding["assurance_authority"], bool)
            or not isinstance(binding["implementation_status"], str)
            or not binding["implementation_status"]
        ):
            raise ProtectionModelError("PROTECTION_APPLICATION_ROLE_BINDING_INVALID")
        kinds: set[str] = set()
        for signed_object in binding["signed_objects"]:
            if (
                not isinstance(signed_object, dict)
                or set(signed_object) != signed_object_fields
                or not isinstance(signed_object["rust_type"], str)
                or not signed_object["rust_type"]
                or not isinstance(signed_object["kind"], str)
                or not signed_object["kind"]
                or signed_object["kind"] in kinds
                or signed_object["schema_major"] != 1
                or signed_object["content_type"]
                != f"application/{signed_object['kind'].replace('.', '-')}+cbor"
                or signed_object["external_aad"]
                != f"{signed_object['kind']}.v{signed_object['schema_major']}"
                or not isinstance(signed_object["subject_binding"], str)
                or not signed_object["subject_binding"]
            ):
                raise ProtectionModelError(
                    "PROTECTION_APPLICATION_ROLE_SIGNED_OBJECT_INVALID"
                )
            kinds.add(signed_object["kind"])
        if binding["assurance_authority"] is not bool(binding["signed_objects"]):
            raise ProtectionModelError("PROTECTION_APPLICATION_ROLE_AUTHORITY_INVALID")
        if role == "DEVELOPMENT_ONLY" and (
            binding["allowed_key_classes"] != ["DEVELOPMENT"]
            or binding["signed_objects"]
            or binding["assurance_authority"] is not False
        ):
            raise ProtectionModelError("PROTECTION_DEVELOPMENT_ROLE_ESCALATION")
    if _records_digest(list(role_bindings.values()), "role") != (
        EXPECTED_APPLICATION_ROLE_BINDINGS_SHA256
    ):
        raise ProtectionModelError("PROTECTION_APPLICATION_ROLE_SEMANTICS_DRIFT")
    components = _unique_objects(
        subjects.get("logical_components"), "subject_id", "LOGICAL_COMPONENT"
    )
    if set(components) != EXPECTED_COMPONENTS:
        raise ProtectionModelError("PROTECTION_LOGICAL_COMPONENTS_INVALID")
    required_component_fields = {
        "subject_id",
        "identity_basis",
        "duties",
        "may_grant_or_widen_authority",
        "plant_command_role",
    }
    if any(
        set(item) != required_component_fields
        or not isinstance(item["identity_basis"], str)
        or not item["identity_basis"]
        or not isinstance(item["duties"], list)
        or not item["duties"]
        or not isinstance(item["plant_command_role"], str)
        for item in components.values()
    ):
        raise ProtectionModelError("PROTECTION_LOGICAL_COMPONENT_SEMANTICS_INVALID")
    if components["gate_application"]["plant_command_role"] != (
        "CONSTRUCT_AFTER_FULL_CONJUNCTION"
    ) or components["gate_transport"]["plant_command_role"] != (
        "PUBLISH_EXACT_VALIDATED_FRAME"
    ):
        raise ProtectionModelError("PROTECTION_GATE_COMPONENT_SPLIT_INVALID")
    for subject_id in (
        "controller",
        "secure_transport_router",
        "trusted_state_producer",
        "lifecycle_service",
        "plant_crebain",
        "observer_auditor",
        "provisioning_operator",
        "external_generation_anchor",
    ):
        if components[subject_id]["may_grant_or_widen_authority"] is not False:
            raise ProtectionModelError("PROTECTION_NON_AUTHORITY_COMPONENT_WIDENS")

    bindings = _unique_objects(
        subjects.get("subject_type_bindings"), "subject_id", "SUBJECT_TYPE_BINDING"
    )
    if set(bindings) != EXPECTED_COMPONENTS:
        raise ProtectionModelError("PROTECTION_SUBJECT_TYPE_BINDING_SET_INVALID")
    binding_fields = {
        "subject_id",
        "transport_principal_ids",
        "application_key_roles",
        "logical_subject_types",
        "binding_status",
    }
    for binding in bindings.values():
        if set(binding) != binding_fields or any(
            not isinstance(binding[field], list)
            or len(set(binding[field])) != len(binding[field])
            or any(not isinstance(value, str) or not value for value in binding[field])
            for field in (
                "transport_principal_ids",
                "application_key_roles",
                "logical_subject_types",
            )
        ):
            raise ProtectionModelError("PROTECTION_SUBJECT_TYPE_BINDING_INVALID")
        if (
            not isinstance(binding["binding_status"], str)
            or not binding["binding_status"]
            or not set(binding["transport_principal_ids"]).issubset(EXPECTED_PRINCIPALS)
            or not set(binding["application_key_roles"]).issubset(EXPECTED_KEY_ROLES)
        ):
            raise ProtectionModelError("PROTECTION_SUBJECT_TYPE_BINDING_INVALID")
    mapped_roles = [
        role
        for binding in bindings.values()
        for role in binding["application_key_roles"]
    ]
    if sorted(mapped_roles) != sorted(set(EXPECTED_KEY_ROLES) - {"DEVELOPMENT_ONLY"}):
        raise ProtectionModelError("PROTECTION_SUBJECT_TYPE_KEY_ROLE_COVERAGE_INVALID")
    mapped_principals = {
        principal
        for binding in bindings.values()
        for principal in binding["transport_principal_ids"]
    }
    if mapped_principals != EXPECTED_PRINCIPALS:
        raise ProtectionModelError("PROTECTION_SUBJECT_TYPE_PRINCIPAL_COVERAGE_INVALID")
    frozen = {
        "logical_components": sorted(
            components.values(), key=lambda item: item["subject_id"]
        ),
        "subject_type_bindings": sorted(
            bindings.values(), key=lambda item: item["subject_id"]
        ),
    }
    if _canonical_digest(frozen) != EXPECTED_COMPONENT_BINDINGS_SHA256:
        raise ProtectionModelError("PROTECTION_COMPONENT_BINDINGS_SEMANTICS_DRIFT")


def _capability_index(principals: dict[str, dict[str, Any]], verb: str) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for principal_id, principal in principals.items():
        routes = principal.get(verb)
        if not isinstance(routes, list) or any(not isinstance(route, str) for route in routes):
            raise ProtectionModelError("PROTECTION_PRINCIPAL_CAPABILITY_INVALID")
        if len(set(routes)) != len(routes):
            raise ProtectionModelError("PROTECTION_PRINCIPAL_CAPABILITY_DUPLICATE")
        for route in routes:
            index.setdefault(route, []).append(principal_id)
    return index


def _verify_profile_and_routes(model: dict[str, Any], profile_path: Path) -> None:
    profile = _load_json(profile_path, MAX_PROFILE_BYTES, "deployment_profile")
    scope = model.get("scope")
    if scope != {
        "profile_id": "haldir-secure-reference-v1",
        "compatibility": "PRE_AUTHORITY_ACL_ONLY",
        "realm": "haldir-ncp",
        "session_id": "uav-1",
        "ncp_protocol_pin": "v0.8.0",
        "default_effect": "DENY",
        "unlisted_authority": "FORBIDDEN",
    }:
        raise ProtectionModelError("PROTECTION_SCOPE_INVALID")
    if (
        profile.get("profile_id") != scope["profile_id"]
        or profile.get("realm") != scope["realm"]
        or profile.get("session_id") != scope["session_id"]
        or profile.get("schema_version") != 1
        or profile.get("controllers") != ["controller-a", "controller-b"]
        or profile.get("zenoh_version") != "1.9.0"
    ):
        raise ProtectionModelError("PROTECTION_PROFILE_IDENTITY_INVALID")
    routes = profile.get("routes")
    profile_principals_raw = profile.get("principals")
    if not isinstance(routes, dict) or len(routes) != 17:
        raise ProtectionModelError("PROTECTION_PROFILE_ROUTES_INVALID")
    if not isinstance(profile_principals_raw, dict) or set(profile_principals_raw) != (
        EXPECTED_PRINCIPALS
    ):
        raise ProtectionModelError("PROTECTION_PROFILE_PRINCIPALS_INVALID")

    model_principals = _unique_objects(
        model["subjects"]["transport_principals"],
        "principal_id",
        "TRANSPORT_PRINCIPAL",
    )
    if set(model_principals) != EXPECTED_PRINCIPALS:
        raise ProtectionModelError("PROTECTION_MODEL_PRINCIPALS_INVALID")
    principal_fields = {
        "principal_id",
        "role",
        "certificate_common_name",
        "publish",
        "subscribe",
        "query",
        "serve",
    }
    for principal_id, source in profile_principals_raw.items():
        modeled = model_principals[principal_id]
        if set(modeled) != principal_fields or modeled != {"principal_id": principal_id, **source}:
            raise ProtectionModelError("PROTECTION_PRINCIPAL_PROFILE_DRIFT")

    verb_to_route_field = {
        "publish": "publishers",
        "subscribe": "subscribers",
        "query": "queriers",
        "serve": "servers",
    }
    capability_indexes = {
        verb: _capability_index(model_principals, verb) for verb in verb_to_route_field
    }
    counts = {verb: sum(len(principal[verb]) for principal in model_principals.values()) for verb in verb_to_route_field}
    if counts != {"publish": 13, "subscribe": 29, "query": 4, "serve": 4}:
        raise ProtectionModelError("PROTECTION_PROFILE_GRANT_COUNTS_INVALID")

    route_resources = _unique_objects(
        model["resources"].get("route_resources"), "route_id", "ROUTE_RESOURCE"
    )
    if set(route_resources) != set(routes):
        raise ProtectionModelError("PROTECTION_ROUTE_RESOURCE_SET_INVALID")
    required_route_fields = {
        "resource_id",
        "route_id",
        "key",
        "semantic_owner",
        "runtime_custodian",
        "publishers",
        "subscribers",
        "queriers",
        "servers",
        "command_effect",
    }
    for route_id, key in routes.items():
        record = route_resources[route_id]
        if (
            set(record) != required_route_fields
            or record["resource_id"] != f"route:{route_id}"
            or record["key"] != key
            or not isinstance(record["semantic_owner"], str)
            or record["semantic_owner"] not in EXPECTED_COMPONENTS
            or not isinstance(record["runtime_custodian"], str)
            or record["runtime_custodian"] not in EXPECTED_COMPONENTS
        ):
            raise ProtectionModelError("PROTECTION_ROUTE_RESOURCE_INVALID")
        for verb, field in verb_to_route_field.items():
            if record[field] != capability_indexes[verb].get(route_id, []):
                raise ProtectionModelError("PROTECTION_ROUTE_CAPABILITY_DRIFT")
        if record["command_effect"] is not (route_id == "final_command"):
            raise ProtectionModelError("PROTECTION_COMMAND_EFFECT_ROUTE_INVALID")
    final = route_resources["final_command"]
    if final["publishers"] != ["gate"] or final["subscribers"] != [
        "observer",
        "robot-crebain",
    ]:
        raise ProtectionModelError("PROTECTION_FINAL_ROUTE_INVALID")
    if _records_digest(list(route_resources.values()), "route_id") != (
        EXPECTED_ROUTE_RESOURCES_SHA256
    ):
        raise ProtectionModelError("PROTECTION_ROUTE_RESOURCE_SEMANTICS_DRIFT")


def _verify_resources_actions_constraints(model: dict[str, Any]) -> tuple[set[str], set[str]]:
    resources = model.get("resources")
    if not isinstance(resources, dict) or set(resources) != {"route_resources", "state_resources"}:
        raise ProtectionModelError("PROTECTION_RESOURCES_INVALID")
    states = _unique_objects(resources.get("state_resources"), "resource_id", "STATE_RESOURCE")
    if set(states) != EXPECTED_STATE_RESOURCES:
        raise ProtectionModelError("PROTECTION_STATE_RESOURCE_SET_INVALID")
    state_fields = {
        "resource_id",
        "semantic_owner",
        "runtime_custodian",
        "integrity",
        "freshness",
        "confidentiality",
        "availability_failure",
    }
    for record in states.values():
        if set(record) != state_fields or any(
            not isinstance(record[field], str) or not record[field]
            for field in state_fields - {"resource_id"}
        ) or record["semantic_owner"] not in EXPECTED_COMPONENTS or record[
            "runtime_custodian"
        ] not in EXPECTED_COMPONENTS:
            raise ProtectionModelError("PROTECTION_STATE_RESOURCE_OWNERSHIP_INVALID")
    secret_resources = {
        "state:gate_application_signing_secret",
        "state:controller_intent_signing_secrets",
        "state:mission_authority_signing_secret",
        "state:admission_authority_signing_secret",
        "state:policy_authority_signing_secret",
        "state:revocation_authority_signing_secret",
        "state:deployment_authority_signing_secret",
        "state:crebain_evidence_signing_secret",
        "state:gate_transport_credentials",
        "state:controller_transport_credentials",
        "state:mission_authority_transport_credentials",
        "state:admission_authority_transport_credentials",
        "state:lifecycle_transport_credentials",
        "state:observer_transport_credentials",
        "state:plant_crebain_transport_credentials",
        "state:router_transport_trust_and_credentials",
        "state:storage_mac_key",
    }
    if any(states[name]["confidentiality"] != "MANDATORY" for name in secret_resources):
        raise ProtectionModelError("PROTECTION_SECRET_CONFIDENTIALITY_INVALID")
    if _records_digest(list(states.values()), "resource_id") != (
        EXPECTED_STATE_RESOURCES_SHA256
    ):
        raise ProtectionModelError("PROTECTION_STATE_RESOURCE_SEMANTICS_DRIFT")

    actions = model.get("actions")
    if not isinstance(actions, dict) or set(actions) != {
        "transport_verbs",
        "authority_operations",
        "decision_outcomes",
        "plant_actions",
        "semantic_invariants",
    }:
        raise ProtectionModelError("PROTECTION_ACTIONS_INVALID")
    if (
        actions["transport_verbs"] != ["publish", "subscribe", "query", "serve"]
        or actions["authority_operations"] != EXPECTED_OPERATIONS
        or actions["decision_outcomes"] != ["ALLOW", "DENY", "ERROR"]
        or actions["plant_actions"] != ["HOLD", "VELOCITY_LOCAL_NED"]
        or actions["semantic_invariants"]
        != {
            "allow_hold": "CREATES_BOUNDED_ZERO_VELOCITY_COMMAND",
            "deny_or_error": "CREATES_NO_NEW_PLANT_COMMAND",
            "haldir_estop": "NOT_CLAIMED",
            "issuance_observation_or_evidence_implies_command_authority": False,
        }
    ):
        raise ProtectionModelError("PROTECTION_ACTION_SEMANTICS_INVALID")

    constraints = _unique_objects(model.get("constraints"), "constraint_id", "CONSTRAINT")
    if {key: value.get("category") for key, value in constraints.items()} != (
        EXPECTED_CONSTRAINTS
    ):
        raise ProtectionModelError("PROTECTION_CONSTRAINT_SET_INVALID")
    if any(
        set(record) != {"constraint_id", "category", "rule"}
        or not isinstance(record["rule"], str)
        or not record["rule"]
        for record in constraints.values()
    ):
        raise ProtectionModelError("PROTECTION_CONSTRAINT_RECORD_INVALID")
    if _records_digest(list(constraints.values()), "constraint_id") != (
        EXPECTED_CONSTRAINTS_SHA256
    ):
        raise ProtectionModelError("PROTECTION_CONSTRAINT_SEMANTICS_DRIFT")
    all_resource_ids = {f"route:{item['route_id']}" for item in resources["route_resources"]} | set(
        states
    )
    all_operations = set(actions["transport_verbs"]) | set(actions["authority_operations"])
    return all_resource_ids, all_operations


def _verify_time_and_roots(model: dict[str, Any]) -> None:
    domains = _unique_objects(model.get("time_domains"), "time_domain_id", "TIME_DOMAIN")
    if set(domains) != set(EXPECTED_TIME_DOMAINS):
        raise ProtectionModelError("PROTECTION_TIME_DOMAIN_SET_INVALID")
    required_fields = {
        "time_domain_id",
        "kind",
        "fields",
        "field_inventory",
        "hot_path_authority",
        "authority_uses",
        "cross_boot_comparable",
        "failure_behavior",
    }
    for domain_id, (kind, hot, cross_boot) in EXPECTED_TIME_DOMAINS.items():
        record = domains[domain_id]
        if (
            set(record) != required_fields
            or record["kind"] != kind
            or record["hot_path_authority"] is not hot
            or record["cross_boot_comparable"] is not cross_boot
            or not isinstance(record["fields"], list)
            or not record["fields"]
            or not isinstance(record["field_inventory"], str)
            or not record["field_inventory"]
            or not isinstance(record["authority_uses"], list)
            or not isinstance(record["failure_behavior"], str)
            or not record["failure_behavior"]
        ):
            raise ProtectionModelError("PROTECTION_TIME_DOMAIN_SEMANTICS_INVALID")
    authority_domains = [
        domain_id for domain_id, record in domains.items() if record["hot_path_authority"]
    ]
    if authority_domains != ["gate_boot_monotonic"]:
        raise ProtectionModelError("PROTECTION_AUTHORITY_CLOCK_AMBIGUOUS")
    if domains["controller_local_provenance"]["authority_uses"] != [] or domains[
        "source_publisher_provenance"
    ]["authority_uses"] != []:
        raise ProtectionModelError("PROTECTION_PROVENANCE_CLOCK_ESCALATION")
    if domains["durable_logical_ratchets"]["authority_uses"] != [
        "same_scope_anti_rollback"
    ]:
        raise ProtectionModelError("PROTECTION_RATCHET_SCOPE_INVALID")
    if domains["boot_or_epoch_scoped_logical_counters"]["authority_uses"] != [
        "same_boot_or_epoch_ordering"
    ]:
        raise ProtectionModelError("PROTECTION_LOGICAL_COUNTER_SCOPE_INVALID")
    if _records_digest(list(domains.values()), "time_domain_id") != (
        EXPECTED_TIME_DOMAINS_SHA256
    ):
        raise ProtectionModelError("PROTECTION_TIME_DOMAIN_SEMANTICS_DRIFT")

    roots = _unique_objects(model.get("trust_roots"), "root_id", "TRUST_ROOT")
    if {root_id: record.get("status") for root_id, record in roots.items()} != (
        EXPECTED_ROOT_STATUS
    ):
        raise ProtectionModelError("PROTECTION_TRUST_ROOT_SET_INVALID")
    root_fields = {
        "root_id",
        "category",
        "status",
        "authority_scope",
        "not_proven",
        "derivable_from_controller_fields",
    }
    if any(
        set(record) != root_fields
        or record["derivable_from_controller_fields"] is not False
        or any(
            not isinstance(record[field], str) or not record[field]
            for field in ("category", "authority_scope", "not_proven")
        )
        for record in roots.values()
    ):
        raise ProtectionModelError("PROTECTION_TRUST_ROOT_SEMANTICS_INVALID")
    if _records_digest(list(roots.values()), "root_id") != EXPECTED_TRUST_ROOTS_SHA256:
        raise ProtectionModelError("PROTECTION_TRUST_ROOT_SEMANTICS_DRIFT")


def _verify_access_policy(
    model: dict[str, Any], all_resource_ids: set[str], all_operations: set[str]
) -> None:
    policy = model.get("access_policy")
    expected_fields = {
        "default_effect",
        "unlisted_subject_resource_action",
        "wildcard_authority_grants",
        "role_name_inference",
        "advisory_or_evidence_grants_authority",
        "route_grants_source",
        "component_rule_semantics",
        "command_construction_subject",
        "command_publication_subject",
        "command_consuming_subjects",
        "final_command_transition",
        "component_rules",
    }
    if not isinstance(policy, dict) or set(policy) != expected_fields:
        raise ProtectionModelError("PROTECTION_ACCESS_POLICY_INVALID")
    if (
        policy["default_effect"] != "DENY"
        or policy["unlisted_subject_resource_action"] != "DENY"
        or policy["wildcard_authority_grants"] is not False
        or policy["role_name_inference"] is not False
        or policy["advisory_or_evidence_grants_authority"] is not False
        or policy["route_grants_source"] != "deploy/secure-reference-v1/profile.json"
        or policy["component_rule_semantics"]
        != "EACH_GRANT_IS_ONE_EXACT_RESOURCE_SET_TIMES_ONE_EXACT_OPERATION_SET"
        or policy["command_construction_subject"] != "gate_application"
        or policy["command_publication_subject"] != "gate_transport"
        or policy["command_consuming_subjects"] != ["plant_crebain"]
    ):
        raise ProtectionModelError("PROTECTION_DEFAULT_DENY_OR_COMMAND_CUSTODY_INVALID")
    rules = _unique_objects(policy["component_rules"], "rule_id", "ACCESS_RULE")
    if set(rules) != EXPECTED_RULES:
        raise ProtectionModelError("PROTECTION_ACCESS_RULE_SET_INVALID")
    if {record.get("subject_id") for record in rules.values()} != EXPECTED_COMPONENTS:
        raise ProtectionModelError("PROTECTION_ACCESS_RULE_SUBJECT_COVERAGE_INVALID")
    resource_operation_pairs: set[tuple[str, str, str]] = set()
    for record in rules.values():
        if set(record) != {"rule_id", "subject_id", "grants"}:
            raise ProtectionModelError("PROTECTION_ACCESS_RULE_FIELDS_INVALID")
        if record["subject_id"] not in EXPECTED_COMPONENTS:
            raise ProtectionModelError("PROTECTION_ACCESS_RULE_UNKNOWN_SUBJECT")
        grants = record["grants"]
        if not isinstance(grants, list) or not grants:
            raise ProtectionModelError("PROTECTION_ACCESS_RULE_GRANTS_INVALID")
        for grant in grants:
            if not isinstance(grant, dict) or set(grant) != {
                "resource_ids",
                "operations",
            }:
                raise ProtectionModelError("PROTECTION_ACCESS_GRANT_FIELDS_INVALID")
            resources = grant["resource_ids"]
            operations = grant["operations"]
            if (
                not isinstance(resources, list)
                or not resources
                or len(set(resources)) != len(resources)
                or not set(resources).issubset(all_resource_ids)
            ):
                raise ProtectionModelError("PROTECTION_ACCESS_RULE_UNKNOWN_RESOURCE")
            if (
                not isinstance(operations, list)
                or not operations
                or len(set(operations)) != len(operations)
                or not set(operations).issubset(all_operations)
            ):
                raise ProtectionModelError("PROTECTION_ACCESS_RULE_UNKNOWN_OPERATION")
            if any("*" in value for value in [*resources, *operations]):
                raise ProtectionModelError("PROTECTION_ACCESS_RULE_WILDCARD")
            for resource_id in resources:
                for operation in operations:
                    pair = (record["subject_id"], resource_id, operation)
                    if pair in resource_operation_pairs:
                        raise ProtectionModelError("PROTECTION_ACCESS_GRANT_DUPLICATE")
                    resource_operation_pairs.add(pair)

    if _canonical_digest(sorted(resource_operation_pairs)) != (
        EXPECTED_ACCESS_TUPLES_SHA256
    ):
        raise ProtectionModelError("PROTECTION_ACCESS_TUPLE_SET_DRIFT")

    transition = policy["final_command_transition"]
    expected_required = [
        constraint_id
        for constraint_id in EXPECTED_CONSTRAINTS
        if not constraint_id.startswith("failure:")
    ]
    if transition != {
        "resource_id": "route:final_command",
        "construction_subject": "gate_application",
        "construction_operation": "construct_frame",
        "publication_subject": "gate_transport",
        "publication_operation": "publish_once",
        "required_constraint_ids": expected_required,
        "failure_constraint_id": "failure:no_new_command",
        "post_exposure_constraint_id": "failure:no_retroactive_erasure",
    }:
        raise ProtectionModelError("PROTECTION_FINAL_COMMAND_TRANSITION_INVALID")
    final_pairs = {
        (subject, operation)
        for subject, resource, operation in resource_operation_pairs
        if resource == "route:final_command"
    }
    if final_pairs != {
        ("gate_transport", "publish_once"),
        ("secure_transport_router", "route_transport"),
        ("plant_crebain", "consume"),
        ("observer_auditor", "observe"),
    }:
        raise ProtectionModelError("PROTECTION_FINAL_COMMAND_ACCESS_INVALID")
    command_operations = {
        (subject, operation)
        for subject, _resource, operation in resource_operation_pairs
        if operation in ("authorize", "construct_frame", "publish_once")
    }
    if any(
        (operation == "construct_frame" and subject != "gate_application")
        or (operation == "publish_once" and subject != "gate_transport")
        or (operation == "authorize" and subject != "gate_application")
        for subject, operation in command_operations
    ):
        raise ProtectionModelError("PROTECTION_COMMAND_AUTHORITY_ESCALATION")

    frozen_policy = dict(policy)
    frozen_policy["component_rules"] = sorted(
        rules.values(), key=lambda item: item["rule_id"]
    )
    if _canonical_digest(frozen_policy) != EXPECTED_ACCESS_POLICY_SHA256:
        raise ProtectionModelError("PROTECTION_ACCESS_POLICY_SEMANTICS_DRIFT")


def _rust_block(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise ProtectionModelError(f"PROTECTION_RUST_MARKER_MISSING:{marker}")
    opening = source.find("{", start)
    if opening < 0:
        raise ProtectionModelError(f"PROTECTION_RUST_BLOCK_INVALID:{marker}")
    depth = 0
    for offset, character in enumerate(source[opening:], start=opening):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : offset]
    raise ProtectionModelError(f"PROTECTION_RUST_BLOCK_UNTERMINATED:{marker}")


def _verify_source_contracts(model: dict[str, Any], repo: Path) -> None:
    sources = model.get("evidence_sources")
    expected = {
        "authority_model": "release/0.9.0/authority-model.json",
        "deployment_profile": "deploy/secure-reference-v1/profile.json",
        "secure_profile_renderer": "tools/secure_zenoh.py",
        "key_role_contract": "crates/haldir-crypto/src/role.rs",
        "cose_profile_contract": "crates/haldir-crypto/src/cose.rs",
        "trust_contract": "crates/haldir-crypto/src/trust.rs",
        "identity_contract": "crates/haldir-contracts/src/ids.rs",
        "session_contract": "crates/haldir-contracts/src/session.rs",
        "intent_contract": "crates/haldir-contracts/src/intent.rs",
        "lease_contract": "crates/haldir-contracts/src/lease.rs",
        "revocation_contract": "crates/haldir-contracts/src/revocation.rs",
        "admission_record_contract": "crates/haldir-admission/src/record.rs",
        "action_contract": "crates/haldir-contracts/src/action.rs",
        "decision_contract": "crates/haldir-contracts/src/receipt.rs",
        "publication_authority_contract": "crates/haldir-contracts/src/status.rs",
        "publication_evidence_contract": "crates/haldir-contracts/src/publication.rs",
        "time_contract": "crates/haldir-core/src/time.rs",
        "trusted_state_contract": "crates/haldir-core/src/snapshot.rs",
        "gate_pipeline_contract": "crates/haldir-gate/src/actor.rs",
        "anti_rollback_contract": "crates/haldir-state/src/anti_rollback.rs",
        "policy_contract": "crates/haldir-policy-native/src/decide.rs",
        "deployment_contract": "crates/haldir-deployment/src/verify.rs",
        "durable_contract": "crates/haldir-durable/src/snapshot.rs",
        "local_anchor_contract": "crates/haldir-durable/src/local_anchor.rs",
        "evidence_contract": "crates/haldir-evidence/src/publication.rs",
        "migration_record": "docs/release/0.9.0/MIGRATION.md",
    }
    if sources != expected:
        raise ProtectionModelError("PROTECTION_EVIDENCE_SOURCES_INVALID")

    def source(name: str) -> str:
        return _read_bounded(
            repo / sources[name], MAX_SOURCE_BYTES, name
        ).decode("utf-8")

    role_source = source("key_role_contract")
    role_block = _rust_block(role_source, "pub const fn as_str")
    roles = re.findall(r'Self::\w+\s*=>\s*"([A-Z_]+)"', role_block)
    if roles != EXPECTED_KEY_ROLES:
        raise ProtectionModelError("PROTECTION_RUST_KEY_ROLE_DRIFT")

    action_source = source("action_contract")
    action_block = _rust_block(action_source, "pub enum RequestedActionV1")
    actions = re.findall(r"^\s{4}([A-Z][A-Za-z0-9]+)\s*\{", action_block, re.MULTILINE)
    normalized = [re.sub(r"(?<!^)(?=[A-Z])", "_", action).upper() for action in actions]
    if normalized != model["actions"]["plant_actions"]:
        raise ProtectionModelError("PROTECTION_RUST_ACTION_DRIFT")

    decision_source = source("decision_contract")
    decision_block = _rust_block(decision_source, "pub enum DecisionOutcomeV1")
    outcomes = re.findall(
        r'^\s*\w+\s*=\s*\d+\s*=>\s*"([A-Z_]+)"', decision_block, re.MULTILINE
    )
    if outcomes != model["actions"]["decision_outcomes"]:
        raise ProtectionModelError("PROTECTION_RUST_DECISION_DRIFT")

    source_fragments = {
        "secure_profile_renderer": (
            '"default_permission": "deny"',
            'acl.get("default_permission") != "deny"',
            'rpc_queryable = f"{profile[\'realm\']}/rpc/*"',
        ),
        "trust_contract": (
            "Resolve exactly one key record by `kid` (no fallback search)",
            "pub struct RevocationSnapshot",
        ),
        "cose_profile_contract": (
            "format!(\"application/{}+cbor\"",
            "format!(\"{kind}.v{schema_major}\")",
            "required_role: KeyRole",
        ),
        "identity_contract": (
            "**distinct** epoch and sequence types with no `From`/`Into`",
            "pub struct GateOutputEpoch",
        ),
        "session_contract": (
            "inseparable NCP session identity pair",
            "correlation, not delivery order",
        ),
        "intent_contract": (
            "consistency claim",
            "no field is",
            "copied into the emitted command",
            'kind "haldir.intent"',
        ),
        "lease_contract": (
            "grants no final-key publication rights",
            "pub struct MissionLeaseV1",
            'kind "haldir.mission_lease"',
        ),
        "revocation_contract": (
            "pub struct AuthorityRevocationV1",
            'kind "haldir.authority_revocation"',
        ),
        "admission_record_contract": (
            "pub struct AdmissionRecordV1",
            'kind "haldir.admission_record"',
        ),
        "publication_authority_contract": (
            "deployment evidence, NOT a plant-issued NCP lease",
            "matches!(self, Self::AclExclusiveV1(_))",
        ),
        "decision_contract": (
            "pub struct DecisionReceiptV1",
            'kind "haldir.decision_receipt"',
        ),
        "publication_evidence_contract": (
            "pub struct PublicationStageEventV1",
            'kind "haldir.publication_stage"',
        ),
        "time_contract": (
            "only time suitable for hot-path validity",
            "Wall-clock and controller timestamps are diagnostic only",
        ),
        "trusted_state_contract": (
            "never used for freshness",
            "Gate receive monotonic time (authoritative freshness basis)",
            "accepted_at_mono",
            "expires_at_mono",
        ),
        "gate_pipeline_contract": (
            "authorization_revision",
            "checked_publication_horizon",
            "gate_t_ns: now.as_nanos()",
        ),
        "anti_rollback_contract": (
            "accept_term",
            "accept_revocation_epoch",
            "boot_counter",
            "DeploymentPackageRatchet",
        ),
        "policy_contract": (
            "checked_duration_since(earlier)",
            "DenySourceStale",
        ),
        "deployment_contract": (
            "separately supplied bootstrap policy and trust",
            "performs no entropy, durable-state, secret, artifact-path, or",
            'DeploymentPackageV1::KIND',
        ),
        "durable_contract": (
            "pub enum AnchorProtection",
            "ExternalNonRewindable",
            "cannot establish anti-rewind",
        ),
        "local_anchor_contract": (
            "remains rewritable",
            "must never satisfy a deployment",
        ),
        "evidence_contract": (
            "does not verify COSE signatures",
            "TimeRegression",
        ),
    }
    for name, fragments in source_fragments.items():
        text = source(name)
        if any(fragment not in text for fragment in fragments):
            raise ProtectionModelError(f"PROTECTION_SOURCE_SEMANTICS_DRIFT:{name}")

    authority = _load_json(repo / sources["authority_model"], MAX_MODEL_BYTES, "authority_model")
    claimed = authority.get("claimed_profile", {})
    separation = authority.get("decision_action_separation", {})
    if (
        claimed.get("profile_id") != model["scope"]["profile_id"]
        or claimed.get("compatibility") != model["scope"]["compatibility"]
        or claimed.get("protected_route")
        != next(
            route["key"]
            for route in model["resources"]["route_resources"]
            if route["route_id"] == "final_command"
        )
        or separation.get("decision_outcomes") != model["actions"]["decision_outcomes"]
        or separation.get("plant_actions") != model["actions"]["plant_actions"]
    ):
        raise ProtectionModelError("PROTECTION_T001_MODEL_DRIFT")


def _verify_claim_scope(model: dict[str, Any]) -> None:
    expected = {
        "protection_inventory": "FROZEN",
        "default_deny_model": "FROZEN",
        "implementation_enforcement": "PARTIAL",
        "protected_credential_custody": "NOT_CLAIMED",
        "mandatory_deployment_package_consumption": "NOT_CLAIMED",
        "authenticated_live_state_and_control_ingress": "NOT_CLAIMED",
        "sealed_capabilities_and_global_handle_exclusivity": "NOT_CLAIMED",
        "external_non_rewindable_durability": "NOT_CLAIMED",
        "complete_mediation": "NOT_CLAIMED",
        "delivery": "NOT_CLAIMED",
        "plant_acceptance_and_application": "NOT_CLAIMED",
        "physical_system_safety": "NOT_CLAIMED",
        "production_deployment_security": "NOT_CLAIMED",
        "native_ncp_1_0": "NOT_CLAIMED",
    }
    if model.get("claim_scope") != expected:
        raise ProtectionModelError("PROTECTION_CLAIM_SCOPE_INVALID")


def _verify_task_closure(repo: Path, task: dict[str, Any]) -> None:
    closure_path = "release/0.9.0/evidence/t002-generated-verification.json"
    closures = [
        item
        for item in task.get("evidence", [])
        if isinstance(item, dict)
        and item.get("kind") == "generated_exact_commit_verification"
    ]
    if (
        len(closures) != 1
        or set(closures[0])
        != {"kind", "path", "implementation_commit", "evidence_tool_commit"}
        or closures[0].get("path") != closure_path
    ):
        raise ProtectionModelError("PROTECTION_T002_LEDGER_CLOSURE_MISSING")
    module_path = repo / "tools/release/generate-task-evidence.py"
    module_spec = importlib.util.spec_from_file_location(
        "haldir_task_evidence_for_protection", module_path
    )
    if module_spec is None or module_spec.loader is None:
        raise ProtectionModelError("PROTECTION_T002_CENTRAL_VERIFIER_UNAVAILABLE")
    core = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(core)
    try:
        record = core.verify_generated_record(repo, repo / closure_path)
    except (core.EvidenceGenerationError, OSError, UnicodeDecodeError, ValueError) as error:
        raise ProtectionModelError("PROTECTION_T002_CENTRAL_VERIFICATION_FAILED") from error
    if (
        record.get("task_id") != "T002"
        or closures[0].get("implementation_commit")
        != record["implementation"]["commit"]
        or closures[0].get("evidence_tool_commit")
        != record["evidence_tool"]["commit"]
    ):
        raise ProtectionModelError("PROTECTION_T002_LEDGER_CLOSURE_MISMATCH")


def _verify_requirements(requirements_path: Path, repo: Path) -> None:
    requirements = _load_json(requirements_path, MAX_REQUIREMENTS_BYTES, "requirements")
    tasks = requirements.get("tasks")
    if not isinstance(tasks, list):
        raise ProtectionModelError("PROTECTION_REQUIREMENTS_TASKS_INVALID")
    by_id = {
        task.get("id"): task
        for task in tasks
        if isinstance(task, dict) and isinstance(task.get("id"), str)
    }
    t001 = by_id.get("T001")
    t002 = by_id.get("T002")
    if not isinstance(t001, dict) or t001.get("status") != "verified":
        raise ProtectionModelError("PROTECTION_PREDECESSOR_NOT_VERIFIED")
    if (
        not isinstance(t002, dict)
        or t002.get("requirement_id") != "HALDIR-0.9-T002"
        or t002.get("dependencies") != ["T001"]
        or t002.get("status") not in {"implemented", "verified"}
    ):
        raise ProtectionModelError("PROTECTION_REQUIREMENT_ENTRY_INVALID")
    evidence = t002.get("evidence")
    required_paths = {
        "docs/release/0.9.0/PROTECTION-MODEL.md",
        "docs/release/0.9.0/MIGRATION.md",
        "docs/CLAIM-LEDGER.md",
        "release/0.9.0/protection-model.json",
        "tools/release/verify-protection-model.py",
        "tools/release/test_verify_protection_model.py",
        "tools/release/generate-task-evidence.py",
        "tools/release/verify-task-evidence.py",
        "release/0.9.0/allowed-signers",
        "deploy/secure-reference-v1/profile.json",
        "crates/haldir-crypto/src/role.rs",
        "crates/haldir-core/src/time.rs",
        "crates/haldir-core/src/snapshot.rs",
    }
    if not isinstance(evidence, list) or not required_paths.issubset(
        {item.get("path") for item in evidence if isinstance(item, dict)}
    ):
        raise ProtectionModelError("PROTECTION_REQUIREMENT_EVIDENCE_INVALID")
    review = t002.get("ten_lens_review")
    if (
        not isinstance(review, dict)
        or set(review) != EXPECTED_LENSES
        or any(not isinstance(value, str) or not value.strip() for value in review.values())
    ):
        raise ProtectionModelError("PROTECTION_REQUIREMENT_REVIEW_INVALID")
    risks = t002.get("residual_risks")
    if not isinstance(risks, list) or not risks or any(
        not isinstance(risk, str) or not risk.strip() for risk in risks
    ):
        raise ProtectionModelError("PROTECTION_REQUIREMENT_RISKS_INVALID")
    if t002["status"] == "verified":
        _verify_task_closure(repo, t002)


def verify(
    model_path: Path,
    repo: Path,
    *,
    profile_path: Path | None = None,
    requirements_path: Path | None = None,
) -> None:
    """Verify the protection inventory and every repository-local binding."""

    model = _load_json(model_path, MAX_MODEL_BYTES, "protection_model")
    if set(model) != EXPECTED_TOP_LEVEL:
        raise ProtectionModelError("PROTECTION_MODEL_TOP_LEVEL_INVALID")
    if (
        model.get("schema_version") != "1.0.0"
        or model.get("requirement_id") != "HALDIR-0.9-T002"
        or model.get("release_target") != "0.9.0"
        or model.get("author") != {"name": "Sepehr Mahmoudian"}
    ):
        raise ProtectionModelError("PROTECTION_MODEL_IDENTITY_INVALID")
    _verify_document(model, repo)
    _verify_identity_and_subjects(model)
    _verify_profile_and_routes(
        model,
        profile_path or repo / "deploy/secure-reference-v1/profile.json",
    )
    all_resources, all_operations = _verify_resources_actions_constraints(model)
    _verify_time_and_roots(model)
    _verify_access_policy(model, all_resources, all_operations)
    _verify_source_contracts(model, repo)
    _verify_claim_scope(model)
    _verify_requirements(
        requirements_path or repo / "release/0.9.0/requirements.json",
        repo,
    )


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    model = repo / "release/0.9.0/protection-model.json"
    try:
        verify(model, repo)
    except ProtectionModelError as error:
        print(f"verify-protection-model: FAIL: {error}", file=sys.stderr)
        return 1
    print("verify-protection-model: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
