#!/usr/bin/env python3
"""Verify the append-only FR-0015 epoch-16 trust-root transition.

FR-0014 remains the signed, activated epoch-15 historical boundary.  Its
verifier and every earlier recovery verifier are inert here.  This bridge
freezes and verifies the exact signed FR-0014 R/Q/A boundary and every signed
linear successor through M06 directly, then validates only the deterministic
FR-0015 R/Q/A sequence and ordinary signed linear milestones after activation.

Epoch-16 hosted-result artifacts convey provenance only and grant no release
authority.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, BinaryIO, NoReturn, Sequence


PARENT = "e98924aa5dfd36169febf9a47aa7a15b44548e31"
PARENT_TREE = "e64a9c27ed1720da7e445ad6b6c881c5665d5781"
PARENT_PARENT = "cf3f2f175602d878884df7daa875296657e35e61"
PARENT_SUBJECT = "supply-chain: define verified cargo-deny assets"
FR0014_REPAIR = "c2ac5b6512d070ecc7f5a560405a05388b7fe86c"
FR0014_REPAIR_PARENT = "62c1e0e0bfe7d81ca6f6ac3cff31c835bbff1089"
FR0014_REPAIR_TREE = "c6a211d1670ac5d423000c78d7dc0b8988e78842"
FR0014_REPAIR_SUBJECT = "release: supersede incomplete epoch-14 recovery"
FR0014_QUALIFICATION = "a628aa9880ab46b8181be6f1873c0503db45b11f"
FR0014_QUALIFICATION_TREE = "eb4d7011556cea987b77afaa29cdc52f3b4c88c8"
FR0014_QUALIFICATION_SUBJECT = "release: qualify epoch-15 audit trust root"
FR0014_ACTIVATION = "116b6ab39051821a70641c4111710ac55d2d2d14"
FR0014_ACTIVATION_TREE = "24087f581393b25c3788bfac90b4a7120e63340f"
FR0014_ACTIVATION_SUBJECT = "release: activate epoch-15 audit trust root"
FR0014_SUCCESSORS = (
    (
        "573d9d28de894e7056010cb7288ed94712809fd3",
        FR0014_ACTIVATION,
        "fc4905533cbeb90e80b571a1a6944de324ac6e90",
        "state: bound anti-rollback persistence",
    ),
    (
        "3f364b83b25ddf42b616d882ed0646e3f063ade4",
        "573d9d28de894e7056010cb7288ed94712809fd3",
        "5f9b5a6f2ea5f442d995ed9e9f8f8882c4bff3bf",
        "policy: bind executable configuration identity",
    ),
    (
        "ec6ac8d251b1e2891827075a7e911fa5288a416b",
        "3f364b83b25ddf42b616d882ed0646e3f063ade4",
        "54d84723b4dd2c0897f4e754b93196c71910837a",
        "audit: track validated policy pipeline",
    ),
    (
        "bfb12613ecc0091267c77282c891208c45444004",
        "ec6ac8d251b1e2891827075a7e911fa5288a416b",
        "5151596916b7081c25d4eac0416a3f2b112ff776",
        "gate: reject active lease replacement",
    ),
    (
        "742e4a4d0b808670f5525fb002f1eefda4a9fe1b",
        "bfb12613ecc0091267c77282c891208c45444004",
        "b8f87981c14034abfa30a4f41d6d7531f3790e86",
        "admission: reject conflicting authority bindings",
    ),
    (
        "cf3f2f175602d878884df7daa875296657e35e61",
        "742e4a4d0b808670f5525fb002f1eefda4a9fe1b",
        "e81f034b74298e8ae91de91f65916c20b36fe54f",
        "state: bind challenge lifetime to session",
    ),
    (
        PARENT,
        PARENT_PARENT,
        PARENT_TREE,
        PARENT_SUBJECT,
    ),
)
RECOVERY_ID = "FR-0015"
REPAIR_SUBJECT = "release: establish epoch-16 audit trust root"
QUALIFICATION_SUBJECT = "release: qualify epoch-16 audit trust root"
ACTIVATION_SUBJECT = "release: activate epoch-16 audit trust root"
PLAN_NAMESPACE = "haldir-framework-recovery-fr-0015-plan-v1"
FR0014_PLAN_NAMESPACE = "haldir-framework-recovery-fr-0014-plan-v1"
FR0014_QUALIFICATION_NAMESPACE = "haldir-framework-recovery-fr-0014-qualification-v1"
FR0014_ACTIVATION_NAMESPACE = "haldir-framework-recovery-fr-0014-activation-v1"
QUALIFICATION_NAMESPACE = "haldir-framework-recovery-fr-0015-qualification-v1"
ACTIVATION_NAMESPACE = "haldir-framework-recovery-fr-0015-activation-v1"
SIGNER_PRINCIPAL = "sepmhn@gmail.com"
SIGNER_FINGERPRINT = "SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU"
AUTHOR_NAME = "Sepehr Mahmoudian"
AUTHOR_EMAIL = "sepmhn@gmail.com"
ALLOWED_SIGNERS_PATH = "release/0.9.0/allowed-signers"
PLAN_PATH = "release/0.9.0/current-head/closures/framework-recovery/FR-0015-plan.json"
QUALIFICATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0015-qualification.json"
)
ACTIVATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0015-activation.json"
)
FR0014_PLAN_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0014-plan.json"
)
FR0014_QUALIFICATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0014-qualification.json"
)
FR0014_ACTIVATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0014-activation.json"
)
MODULE_PATH = "tools/release/framework_recovery_fr_0015.py"
CAPTURE_PATH = "tools/release/framework_recovery_fr_0015_capture.py"
RESULT_PATH = "tools/release/framework_recovery_fr_0015_result.py"
BRIDGE_PATH = "tools/release/verify-framework-recovery-fr-0015.py"
TEST_PATH = "tools/release/test_verify_framework_recovery_fr_0015.py"
TRUSTED_ROOT_PATH = "tools/release/sigstore-public-good-trusted-root.jsonl"
GATE_PATH = "tools/release/current-audit-gate.sh"
PIN_VERIFIER_PATH = "tools/verify-ci-pins.py"
SOURCE_PIN_VERIFIER_PATH = "tools/verify-pins.py"
SUPPLY_PIN_PATH = "tools/pins.toml"
CARGO_DENY_INSTALLER_PATH = "tools/pinned_cargo_deny.py"
CARGO_DENY_TEST_PATH = "tools/test_pinned_cargo_deny.py"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
FORMAL_WORKFLOW_PATH = ".github/workflows/formal.yml"

CORE_PATHS = (
    CI_WORKFLOW_PATH,
    FORMAL_WORKFLOW_PATH,
    PIN_VERIFIER_PATH,
    SOURCE_PIN_VERIFIER_PATH,
    SUPPLY_PIN_PATH,
    CARGO_DENY_INSTALLER_PATH,
    CARGO_DENY_TEST_PATH,
    GATE_PATH,
    MODULE_PATH,
    TRUSTED_ROOT_PATH,
    CAPTURE_PATH,
    RESULT_PATH,
    BRIDGE_PATH,
    TEST_PATH,
)
REPAIR_STATUSES = {
    CI_WORKFLOW_PATH: "M",
    FORMAL_WORKFLOW_PATH: "M",
    PLAN_PATH: "A",
    PIN_VERIFIER_PATH: "M",
    SOURCE_PIN_VERIFIER_PATH: "M",
    SUPPLY_PIN_PATH: "M",
    CARGO_DENY_INSTALLER_PATH: "M",
    CARGO_DENY_TEST_PATH: "M",
    GATE_PATH: "M",
    MODULE_PATH: "A",
    CAPTURE_PATH: "A",
    RESULT_PATH: "A",
    BRIDGE_PATH: "A",
    TEST_PATH: "A",
}
REPAIR_MODES = {
    CI_WORKFLOW_PATH: "100644",
    PLAN_PATH: "100644",
    FORMAL_WORKFLOW_PATH: "100644",
    PIN_VERIFIER_PATH: "100755",
    SOURCE_PIN_VERIFIER_PATH: "100644",
    SUPPLY_PIN_PATH: "100644",
    CARGO_DENY_INSTALLER_PATH: "100644",
    CARGO_DENY_TEST_PATH: "100644",
    GATE_PATH: "100755",
    MODULE_PATH: "100644",
    CAPTURE_PATH: "100755",
    RESULT_PATH: "100755",
    BRIDGE_PATH: "100755",
    TEST_PATH: "100644",
    TRUSTED_ROOT_PATH: "100644",
}

EVIDENCE_ROOT = "release/0.9.0/current-head/evidence"
REPAIR_CI_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-ci-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-ci-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-ci-attestation.json",
)
REPAIR_FORMAL_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-formal-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-formal-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-formal-attestation.json",
)
LOCAL_PATH = f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-local.json"
QUALIFICATION_EVIDENCE_PATHS = (
    *REPAIR_CI_PATHS,
    *REPAIR_FORMAL_PATHS,
    LOCAL_PATH,
)
QUALIFICATION_STATUSES = {
    QUALIFICATION_PATH: "A",
    **{path: "A" for path in QUALIFICATION_EVIDENCE_PATHS},
}
QUALIFICATION_CI_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-q-ci-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-q-ci-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-q-ci-attestation.json",
)
QUALIFICATION_FORMAL_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-q-formal-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-q-formal-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-q-formal-attestation.json",
)
BRANCH_PROTECTION_PATH = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-branch-protection.json"
)
ACTIVATION_EVIDENCE_PATHS = (
    *QUALIFICATION_CI_PATHS,
    *QUALIFICATION_FORMAL_PATHS,
    BRANCH_PROTECTION_PATH,
)
ACTIVATION_STATUSES = {
    ACTIVATION_PATH: "A",
    **{path: "A" for path in ACTIVATION_EVIDENCE_PATHS},
}

FR0014_BOUNDARY_RECORDS = {
    ALLOWED_SIGNERS_PATH: {
        "git_mode": "100644",
        "git_object_id": "7e563049b65dc6761e76b7d0c96c1cc10bd5c0dc",
        "sha256": "88eddddf1b3a6d0176acf2ec88b1d3c120453e2658651c49b82d41057caa78ed",
        "bytes": 98,
    },
    FR0014_PLAN_PATH: {
        "git_mode": "100644",
        "git_object_id": "f6c68a0e2a7778fb2c2cc6364c6835940e3ea476",
        "sha256": "d21a12f096c7bddc5a62f2ccb92bec3ddc3b50736426a93f121720448c511d05",
        "bytes": 44_282,
    },
    FR0014_QUALIFICATION_PATH: {
        "git_mode": "100644",
        "git_object_id": "72a28c3adce16a0acfed08a1d1016dbcc6b53074",
        "sha256": "15f4929d4bb7af1485b56765029bdb9cf29539579844a6b8bf2f4fbdec69d907",
        "bytes": 18_286,
    },
    FR0014_ACTIVATION_PATH: {
        "git_mode": "100644",
        "git_object_id": "ea694bf4fd967454a3ef4d2853d1ef6a54d80e73",
        "sha256": "85d72e88953550147c83d692b5747cc377345a094b7ab363456e92e2324507c2",
        "bytes": 23_327,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0014-r-ci-attestation.json": {
        "git_mode": "100644",
        "git_object_id": "e3a579e430c6452647b8589e1dda1345e5927b21",
        "sha256": "4f115b23c70efcea52f3852db04bf5c4eb053b6b1ffb97ae0a80662a77617867",
        "bytes": 10_347,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0014-r-ci-capture.json": {
        "git_mode": "100644",
        "git_object_id": "43b5d59027fe7c0b63feb0df66efa6a6711e1470",
        "sha256": "d1bab48ff3f0c92709715f39b7035158a8ebf2c7353f0a9642ab99ca7588d5c1",
        "bytes": 64_530,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0014-r-ci-result.json": {
        "git_mode": "100644",
        "git_object_id": "780a7b602d40c9eb36accc7bfedf2c18783da0e2",
        "sha256": "a4a57d526d16707503d8b829b9f7abdd62176d8255c20bce2f04c8945515db12",
        "bytes": 2_467,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0014-r-formal-attestation.json": {
        "git_mode": "100644",
        "git_object_id": "17ac9e6c299c900262aeb71717966b7f039cc1f0",
        "sha256": "a37445792ea2a11074778f84b8d266c7b65f9473139c8d187858a99327d881c6",
        "bytes": 10_380,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0014-r-formal-capture.json": {
        "git_mode": "100644",
        "git_object_id": "33058af6e2d262e13ee6cff6c95d9375fc805e96",
        "sha256": "4691f057a20dbbe80a00fbd62dcb58acec0c503cc04a4380c5d39f6f6ed076d9",
        "bytes": 32_698,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0014-r-formal-result.json": {
        "git_mode": "100644",
        "git_object_id": "752610ddb3502ee79530472c50a356de0153aa43",
        "sha256": "557fc456a6d1240575863c9ed26318d7f2eaab349b638cba09127b598238390c",
        "bytes": 2_446,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0014-r-local.json": {
        "git_mode": "100644",
        "git_object_id": "5022a1ede48e0ad6b1a9c69367ff056aad008daa",
        "sha256": "979d82232ccbc3059a20e9c5a3094a6f8e46082ae40685e87f9881e3937d4377",
        "bytes": 3_586,
    },
    TRUSTED_ROOT_PATH: {
        "git_mode": "100644",
        "git_object_id": "7fa44c8fde4afb1dc889c4284245b1dbcf30525d",
        "sha256": "3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1",
        "bytes": 5_748,
    },
    "tools/release/framework_recovery_fr_0014.py": {
        "git_mode": "100644",
        "git_object_id": "bfc4252775e977435328db5a68ebc73ca7b113af",
        "sha256": "ba48f97b611aace5e038764e91ec5569bb977130cc40489bf7558aad83a8eae7",
        "bytes": 33_411,
    },
    "tools/release/framework_recovery_fr_0014_capture.py": {
        "git_mode": "100755",
        "git_object_id": "dbf6562b7d1a02a7d61e79a49be25a6a34372a70",
        "sha256": "ce21ad28b85f069d0192ad6076ff69523c9ef16eaf8d80372d2c4b7dc7b06c56",
        "bytes": 34_800,
    },
    "tools/release/framework_recovery_fr_0014_result.py": {
        "git_mode": "100755",
        "git_object_id": "c6b3cb6e87867f000e48b610a2a56d3a088383eb",
        "sha256": "f9282aa0ecd5f9c7bcd546fecf04b6b3e2534ee5c8050db03b382ccde0a66bac",
        "bytes": 9_934,
    },
    "tools/release/test_verify_framework_recovery_fr_0014.py": {
        "git_mode": "100644",
        "git_object_id": "cf02a5c1f47c89144c5d186e2e5de516fb08255d",
        "sha256": "38c6fa9b27141240117191285d65ad9cd41d28cd527f00c841be6e028c8ff3f9",
        "bytes": 116_615,
    },
    "tools/release/verify-framework-recovery-fr-0014.py": {
        "git_mode": "100755",
        "git_object_id": "6de5106e10505050b88924bb8f5252892076511a",
        "sha256": "be94190428c56c966d6d8df107febfc0fa022b2c4de1c7abc38536b63871a880",
        "bytes": 119_655,
    },
}

HISTORICAL_RECOVERY_TOOL_PATHS = frozenset(
    {
        "tools/release/framework_recovery_fr_0010.py",
        "tools/release/framework_recovery_fr_0010_capture.py",
        "tools/release/framework_recovery_fr_0010_result.py",
        "tools/release/test_verify_framework_recovery_fr_0010.py",
        "tools/release/verify-framework-recovery-fr-0010.py",
        "tools/release/framework_recovery_fr_0011.py",
        "tools/release/framework_recovery_fr_0011_capture.py",
        "tools/release/framework_recovery_fr_0011_result.py",
        "tools/release/test_verify_framework_recovery_fr_0011.py",
        "tools/release/verify-framework-recovery-fr-0011.py",
        "tools/release/framework_recovery_fr_0012.py",
        "tools/release/framework_recovery_fr_0012_capture.py",
        "tools/release/framework_recovery_fr_0012_result.py",
        "tools/release/test_verify_framework_recovery_fr_0012.py",
        "tools/release/verify-framework-recovery-fr-0012.py",
        "tools/release/framework_recovery_fr_0013.py",
        "tools/release/framework_recovery_fr_0013_capture.py",
        "tools/release/framework_recovery_fr_0013_result.py",
        "tools/release/test_verify_framework_recovery_fr_0013.py",
        "tools/release/verify-framework-recovery-fr-0013.py",
        "tools/release/framework_recovery_fr_0014.py",
        "tools/release/framework_recovery_fr_0014_capture.py",
        "tools/release/framework_recovery_fr_0014_result.py",
        "tools/release/test_verify_framework_recovery_fr_0014.py",
        "tools/release/verify-framework-recovery-fr-0014.py",
    }
)

FR0013_FORBIDDEN_COMPLETION_PATHS = frozenset(
    {
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0013-activation.json"
        ),
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0013-q-ci-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0013-q-ci-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0013-q-ci-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0013-q-formal-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0013-q-formal-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0013-q-formal-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0013-branch-protection.json",
    }
)

FR0012_FORBIDDEN_COMPLETION_PATHS = frozenset(
    {
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0012-qualification.json"
        ),
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0012-activation.json"
        ),
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-r-ci-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-r-ci-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-r-ci-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-r-formal-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-r-formal-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-r-formal-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-r-local.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-q-ci-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-q-ci-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-q-ci-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-q-formal-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-q-formal-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-q-formal-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0012-branch-protection.json",
    }
)

FR0011_FORBIDDEN_COMPLETION_PATHS = frozenset(
    {
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0011-qualification.json"
        ),
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0011-activation.json"
        ),
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-c5-ci.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-c5-ci-logs.zip",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-c5-formal.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-c5-formal-logs.zip",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-r-ci-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-r-ci-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-r-ci-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-r-formal-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-r-formal-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-r-formal-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-r-local.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-q-ci-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-q-ci-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-q-ci-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-q-formal-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-q-formal-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-q-formal-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0011-branch-protection.json",
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0011-design-capture.json"
        ),
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0011-design-provider-response.json"
        ),
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0011-design-response.json"
        ),
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0011-implementation-capture.json"
        ),
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0011-implementation-provider-response.json"
        ),
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0011-implementation-response.json"
        ),
    }
)
FR0010_FORBIDDEN_COMPLETION_PATHS = frozenset(
    {
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0010-qualification.json"
        ),
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0010-activation.json"
        ),
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-c5-ci.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-c5-ci-logs.zip",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-c5-formal.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-c5-formal-logs.zip",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-ci-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-ci-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-ci-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-formal-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-formal-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-formal-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-local.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-ci-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-ci-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-ci-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-formal-capture.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-formal-result.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-formal-attestation.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-branch-protection.json",
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0010-design-capture.json"
        ),
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0010-design-response.json"
        ),
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0010-implementation-capture.json"
        ),
        (
            "release/0.9.0/current-head/reviews/"
            "framework-recovery-fr-0010-implementation-response.json"
        ),
    }
)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_GIT_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_TRUSTED_ROOT_BYTES = 8 * 1024 * 1024
MAX_LOCAL_TOOL_BYTES = 256 * 1024 * 1024
TRUSTED_ROOT_BYTES = 5_748
TRUSTED_ROOT_SHA256 = "3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1"
GH_CLI_VERSION = "2.96.0"
GH_CLI_LINUX_AMD64_ARCHIVE = (
    "https://github.com/cli/cli/releases/download/v2.96.0/gh_2.96.0_linux_amd64.tar.gz"
)
GH_CLI_LINUX_AMD64_ARCHIVE_SHA256 = (
    "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60"
)
GH_CLI_LINUX_AMD64_ARCHIVE_BYTES = 14_652_560
GH_CLI_LINUX_AMD64_BINARY_SHA256 = (
    "56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40"
)
GH_CLI_LINUX_AMD64_BINARY_BYTES = 40_722_594
GH_CLI_MACOS_ARM64_ARCHIVE = (
    "https://github.com/cli/cli/releases/download/v2.96.0/gh_2.96.0_macOS_arm64.zip"
)
GH_CLI_MACOS_ARM64_ARCHIVE_SHA256 = (
    "f23a0c37d963aacc3bed703ccbd59b41c5ca22101fab7f00eb2b7cad23aba463"
)
GH_CLI_MACOS_ARM64_ARCHIVE_BYTES = 13_950_131
GH_CLI_MACOS_ARM64_BINARY_SHA256 = (
    "b1d6c442fde99ca27c04e1e74d624895abe37785f4a3e9e9b684bf7586ce4bc8"
)
GH_CLI_MACOS_ARM64_BINARY_BYTES = 38_817_216
MAX_SUCCESSOR_PATHS = 512
GITHUB_ACTIONS_APP_ID = 15_368
REQUIRED_PRE_ACCEPT_CHECKS = frozenset(
    {
        "build-test",
        "feature-matrix",
        "macos-compile",
        "clean-build",
        "supply-chain",
        "interop",
        "tlc-model-check",
    }
)
MAIN_RULESET_NAME = "haldir-main-writer-allowlist"
MAIN_RULESET_OWNER_ID = 10_104_569
REPOSITORY_ID = 1_292_802_592
REPOSITORY_NAME = "haldir"
REPOSITORY_FULL_NAME = "sepahead/haldir"
REPOSITORY_DEFAULT_BRANCH = "main"
REPOSITORY_OWNER_LOGIN = "sepahead"
BRANCH_PROTECTION_EXPECTED_POLICY = {
    "required_signatures": {"enabled": True},
    "required_status_checks": {
        "strict": True,
        "checks": [
            {"context": context, "app_id": GITHUB_ACTIONS_APP_ID}
            for context in sorted(REQUIRED_PRE_ACCEPT_CHECKS)
        ],
    },
    "enforce_admins": True,
    "required_pull_request_reviews": None,
    "restrictions": None,
    "required_linear_history": True,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "block_creations": False,
    "required_conversation_resolution": False,
    "lock_branch": False,
    "allow_fork_syncing": False,
}

PROTECTED_AFTER_ACTIVATION = frozenset(
    {
        *CORE_PATHS,
        PLAN_PATH,
        QUALIFICATION_PATH,
        ACTIVATION_PATH,
        *QUALIFICATION_EVIDENCE_PATHS,
        *ACTIVATION_EVIDENCE_PATHS,
        *FR0014_BOUNDARY_RECORDS,
        *HISTORICAL_RECOVERY_TOOL_PATHS,
        *FR0013_FORBIDDEN_COMPLETION_PATHS,
        *FR0012_FORBIDDEN_COMPLETION_PATHS,
        *FR0011_FORBIDDEN_COMPLETION_PATHS,
        *FR0010_FORBIDDEN_COMPLETION_PATHS,
        ALLOWED_SIGNERS_PATH,
        "tools/release/verify-current-audit.py",
        "tools/release/test_verify_current_audit_fr_0009.py",
    }
)
PROTECTED_RECOVERY_PREFIXES_AFTER_ACTIVATION = (
    "release/0.9.0/current-head/closures/framework-recovery/",
    "release/0.9.0/current-head/evidence/framework-recovery-fr-",
    "release/0.9.0/current-head/reviews/framework-recovery-fr-",
)


class BridgeError(RuntimeError):
    """One fail-closed epoch-16 bridge error."""


def _fail(code: str) -> NoReturn:
    raise BridgeError(code)


def canonical_json_bytes(value: Any, *, pretty: bool = True) -> bytes:
    """Return the sole accepted JSON representation."""

    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
            sort_keys=True,
        )
        + ("\n" if pretty else "")
    ).encode("utf-8")


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git(
    repo: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    limit: int = MAX_GIT_BYTES,
) -> bytes:
    completed = subprocess.run(
        ("/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments),
        cwd=repo,
        env=_git_environment(),
        input=input_bytes,
        stdin=None if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if (
        completed.returncode != 0
        or len(completed.stdout) > limit
        or len(completed.stderr) > 256 * 1024
    ):
        _fail("FR0015_GIT:" + (arguments[0] if arguments else "missing"))
    return completed.stdout


def _metadata(repo: Path, commit: str) -> dict[str, str]:
    raw = _git(
        repo,
        "show",
        "-s",
        "--format=%H%x00%P%x00%T%x00%an%x00%ae%x00%cn%x00%ce%x00%s%x00%aI%x00%cI",
        commit,
        limit=64 * 1024,
    )
    fields = raw.rstrip(b"\n").split(b"\0")
    if len(fields) != 10:
        _fail("FR0015_COMMIT_METADATA")
    try:
        values = [field.decode("utf-8") for field in fields]
    except UnicodeDecodeError:
        _fail("FR0015_COMMIT_METADATA")
    keys = (
        "commit",
        "parents",
        "tree",
        "author_name",
        "author_email",
        "committer_name",
        "committer_email",
        "subject",
        "author_date",
        "committer_date",
    )
    result = dict(zip(keys, values, strict=True))
    if (
        HEX40.fullmatch(result["commit"]) is None
        or HEX40.fullmatch(result["tree"]) is None
        or len(result["parents"].split()) > 1
    ):
        _fail("FR0015_COMMIT_METADATA")
    return result


def _verify_commit_argv(repo: Path, commit: str) -> tuple[str, ...]:
    return (
        "/usr/bin/git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        f"gpg.ssh.allowedSignersFile={repo / ALLOWED_SIGNERS_PATH}",
        "-c",
        f"gpg.ssh.revocationFile={os.devnull}",
        "-c",
        "gpg.ssh.program=/usr/bin/ssh-keygen",
        "-c",
        "gpg.format=ssh",
        "verify-commit",
        commit,
    )


def _verify_commit_identity(
    repo: Path,
    commit: str,
    *,
    parent: str,
    subject: str | None,
) -> dict[str, str]:
    metadata = _metadata(repo, commit)
    if (
        metadata["parents"] != parent
        or (subject is not None and metadata["subject"] != subject)
        or metadata["author_name"] != AUTHOR_NAME
        or metadata["author_email"] != AUTHOR_EMAIL
        or metadata["committer_name"] != AUTHOR_NAME
        or metadata["committer_email"] != AUTHOR_EMAIL
        or metadata["author_date"] != metadata["committer_date"]
    ):
        _fail("FR0015_COMMIT_IDENTITY")
    completed = subprocess.run(
        _verify_commit_argv(repo, commit),
        cwd=repo,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    expected = (
        f'Good "git" signature for {SIGNER_PRINCIPAL} with ED25519 key '
        f"{SIGNER_FINGERPRINT}\n"
    ).encode("ascii")
    if (
        completed.returncode != 0
        or completed.stdout != b""
        or completed.stderr != expected
    ):
        _fail("FR0015_COMMIT_SIGNATURE")
    return metadata


def _verify_provisional_commit_identity(
    repo: Path,
    commit: str,
    *,
    parent: str,
    subject: str,
) -> dict[str, str]:
    metadata = _metadata(repo, commit)
    if (
        metadata["parents"] != parent
        or metadata["subject"] != subject
        or metadata["author_name"] != AUTHOR_NAME
        or metadata["author_email"] != AUTHOR_EMAIL
        or metadata["committer_name"] != AUTHOR_NAME
        or metadata["committer_email"] != AUTHOR_EMAIL
        or metadata["author_date"] != metadata["committer_date"]
    ):
        _fail("FR0015_PROVISIONAL_COMMIT_IDENTITY")
    return metadata


def _changed_statuses(repo: Path, parent: str, commit: str) -> dict[str, str]:
    raw = _git(
        repo,
        "diff-tree",
        "--no-commit-id",
        "--no-renames",
        "--root",
        "-r",
        "--name-status",
        "-z",
        parent,
        commit,
    )
    parts = raw.split(b"\0")
    if parts[-1:] == [b""]:
        parts.pop()
    if len(parts) % 2:
        _fail("FR0015_DIFF_GRAMMAR")
    result: dict[str, str] = {}
    for index in range(0, len(parts), 2):
        try:
            status = parts[index].decode("ascii")
            path = parts[index + 1].decode("utf-8")
        except UnicodeDecodeError:
            _fail("FR0015_DIFF_GRAMMAR")
        if (
            status not in {"A", "M", "D"}
            or path in result
            or path.startswith("/")
            or "//" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            _fail("FR0015_DIFF_GRAMMAR")
        result[path] = status
    return dict(sorted(result.items()))


def _tree_entry(repo: Path, commit: str, path: str) -> dict[str, str]:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path, limit=64 * 1024)
    if raw.count(b"\0") != 1 or not raw.endswith(b"\0"):
        _fail("FR0015_TREE_ENTRY:" + path)
    try:
        header, observed = raw[:-1].split(b"\t", 1)
        mode, object_type, oid = header.decode("ascii").split(" ")
        decoded = observed.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        _fail("FR0015_TREE_ENTRY:" + path)
    if (
        decoded != path
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or HEX40.fullmatch(oid) is None
    ):
        _fail("FR0015_TREE_ENTRY:" + path)
    return {"mode": mode, "type": object_type, "oid": oid}


def _file(repo: Path, commit: str, path: str, limit: int = MAX_JSON_BYTES) -> bytes:
    entry = _tree_entry(repo, commit, path)
    return _git(repo, "cat-file", "blob", entry["oid"], limit=limit)


def file_record(repo: Path, commit: str, path: str) -> dict[str, Any]:
    entry = _tree_entry(repo, commit, path)
    payload = _file(repo, commit, path, MAX_GIT_BYTES)
    return {
        "path": path,
        "git_mode": entry["mode"],
        "git_object_type": "blob",
        "git_object_id": entry["oid"],
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _read_json(repo: Path, commit: str, path: str) -> tuple[dict[str, Any], bytes]:
    payload = _file(repo, commit, path)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0015_JSON:" + path)
    if not isinstance(value, dict) or payload != canonical_json_bytes(value):
        _fail("FR0015_JSON_CANONICAL:" + path)
    return value, payload


def _verify_detached(
    repo: Path,
    record: Any,
    payload: bytes,
    *,
    namespace: str,
) -> None:
    if (
        not isinstance(record, dict)
        or set(record)
        != {
            "format",
            "namespace",
            "principal",
            "key_fingerprint",
            "signature",
        }
        or record["format"] != "ssh"
        or record["namespace"] != namespace
        or record["principal"] != SIGNER_PRINCIPAL
        or record["key_fingerprint"] != SIGNER_FINGERPRINT
        or not isinstance(record["signature"], str)
        or len(record["signature"]) > 16 * 1024
    ):
        _fail("FR0015_DETACHED_SIGNATURE")
    with tempfile.TemporaryDirectory(prefix="haldir-fr0015-signature-") as name:
        signature_path = Path(name) / "signature"
        signature_path.write_text(record["signature"], encoding="ascii")
        completed = subprocess.run(
            (
                "/usr/bin/ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(repo / ALLOWED_SIGNERS_PATH),
                "-I",
                SIGNER_PRINCIPAL,
                "-n",
                namespace,
                "-s",
                str(signature_path),
            ),
            cwd=repo,
            env=_git_environment(),
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    expected = (
        f'Good "{namespace}" signature for {SIGNER_PRINCIPAL} with ED25519 key '
        f"{SIGNER_FINGERPRINT}\n"
    ).encode("ascii")
    if (
        completed.returncode != 0
        or completed.stdout != expected
        or completed.stderr != b""
    ):
        _fail("FR0015_DETACHED_SIGNATURE")


def _core_patch(repo: Path, repair_commit: str) -> bytes:
    return _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "-c",
        "core.attributesFile=/dev/null",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--text",
        "--no-renames",
        "--no-color",
        "--full-index",
        "--binary",
        f"{PARENT}..{repair_commit}",
        "--",
        *CORE_PATHS,
    )


def _core_diff(repo: Path, repair_commit: str) -> dict[str, Any]:
    patch = _core_patch(repo, repair_commit)
    return {
        "base": PARENT,
        "target": "SIGNED_COMMIT_CONTAINING_THIS_PLAN",
        "paths": list(CORE_PATHS),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "patch_bytes": len(patch),
        "patch_lines": len(patch.splitlines()),
    }


def _authority(state: str) -> dict[str, Any]:
    return {
        "state": state,
        "framework_epoch": 16,
        "overall_release_status": "NO_GO",
        "release_authorized": False,
        "deployment_authorized": False,
        "publication_authorized": False,
        "tag_authorized": False,
        "github_release_authorized": False,
        "doi_authorized": False,
        "archive_authorized": False,
    }


def _validate_authority(
    value: Any,
    *,
    state: str,
    framework_epoch: int = 16,
) -> None:
    expected = _authority(state)
    expected["framework_epoch"] = framework_epoch
    boolean_fields = {
        "release_authorized",
        "deployment_authorized",
        "publication_authorized",
        "tag_authorized",
        "github_release_authorized",
        "doi_authorized",
        "archive_authorized",
    }
    if (
        not isinstance(value, dict)
        or set(value) != set(expected)
        or type(value.get("framework_epoch")) is not int
        or any(type(value.get(field)) is not bool for field in boolean_fields)
        or value != expected
    ):
        _fail("FR0015_AUTHORITY_SCHEMA")


def expected_plan(repo: Path, repair_commit: str) -> dict[str, Any]:
    """Return the exact unsigned FR-0015 repair plan."""

    limitations = [
        (
            "GitHub OIDC proves the isolated attestation workflow identity; "
            "the producer result remains a statement from repository code."
        ),
        (
            "The epoch-16 artifact syntax is an evidence transport only and "
            "confers no release authority."
        ),
        (
            "cargo-deny and RustSec acquisition still require network "
            "availability, but exact size and SHA-256 identities are checked "
            "before either input is installed or executed."
        ),
        (
            "The dependency-policy execution is frozen and network-isolated; "
            "the pinned RustSec snapshot is rejected after its finite 90-day "
            "staleness window and requires an intentional signed refresh."
        ),
        (
            "Branch-protection API evidence is a TLS-observed snapshot of "
            "mutable external state, not durable cryptographic proof."
        ),
        (
            "Epoch 16 performs no branch-control mutation. Its activation "
            "captures the existing protected state at the qualification "
            "commit through bounded GET requests and claims no durable "
            "external-state proof."
        ),
        (
            "Activation necessarily binds qualification-main hosted proof; "
            "the activation commit cannot contain hosted proof of itself."
        ),
        (
            "Offline successor verification proves signature, ancestry, and "
            "protected-path scope, but cannot prove mutable hosted settings."
        ),
        (
            "Bounded subprocess cleanup terminates descendants that remain in "
            "the child process group. A hostile descendant that successfully "
            "creates a new session or double-forks outside that group can "
            "escape this local process-tree boundary. No host-resource "
            "containment or availability guarantee is claimed."
        ),
        (
            "The owner/admin can mutate external settings; owner-account or "
            "GitHub control-plane compromise is outside this local guarantee."
        ),
        (
            "This bridge grants no release, deployment, publication, tag, "
            "archive, DOI, or GitHub Release authority."
        ),
    ]
    return {
        "schema_version": "1.0.0",
        "recovery_id": RECOVERY_ID,
        "release_target": "0.9.0",
        "protocol_parent": {"commit": PARENT, "tree": PARENT_TREE},
        "repair_identity": {
            "subject": REPAIR_SUBJECT,
            "commit": "SIGNED_COMMIT_CONTAINING_THIS_PLAN",
            "required_parent": PARENT,
        },
        "repair_scope": dict(sorted(REPAIR_STATUSES.items())),
        "core_records": [file_record(repo, repair_commit, path) for path in CORE_PATHS],
        "core_diff": _core_diff(repo, repair_commit),
        "legacy_boundary": {
            "state": "HISTORICAL_SIGNED_FR_0014_ACTIVE_BOUNDARY",
            "commit": PARENT,
            "tree": PARENT_TREE,
            "parent": PARENT_PARENT,
            "subject": PARENT_SUBJECT,
            "repair_commit": FR0014_REPAIR,
            "repair_tree": FR0014_REPAIR_TREE,
            "repair_parent": FR0014_REPAIR_PARENT,
            "repair_subject": FR0014_REPAIR_SUBJECT,
            "qualification_commit": FR0014_QUALIFICATION,
            "qualification_tree": FR0014_QUALIFICATION_TREE,
            "activation_commit": FR0014_ACTIVATION,
            "activation_tree": FR0014_ACTIVATION_TREE,
            "fr_0014_state": "ACTIVE",
            "fr_0014_successor_verifier_state": "RETIRED_AT_FR_0015_REPAIR",
            "fr_0014_successor_verifier_executed": False,
            "earlier_recovery_python_executed": False,
            "fr_0014_plan_namespace": FR0014_PLAN_NAMESPACE,
            "fr_0014_qualification_namespace": FR0014_QUALIFICATION_NAMESPACE,
            "fr_0014_activation_namespace": FR0014_ACTIVATION_NAMESPACE,
            "signed_successor_chain": [
                {
                    "commit": commit,
                    "parent": parent,
                    "tree": tree,
                    "subject": subject,
                }
                for commit, parent, tree, subject in FR0014_SUCCESSORS
            ],
            "fr_0013_forbidden_completion_paths": sorted(
                FR0013_FORBIDDEN_COMPLETION_PATHS
            ),
            "fr_0012_forbidden_completion_paths": sorted(
                FR0012_FORBIDDEN_COMPLETION_PATHS
            ),
            "fr_0011_forbidden_completion_paths": sorted(
                FR0011_FORBIDDEN_COMPLETION_PATHS
            ),
            "fr_0010_forbidden_completion_paths": sorted(
                FR0010_FORBIDDEN_COMPLETION_PATHS
            ),
            "historical_recovery_tool_paths": sorted(HISTORICAL_RECOVERY_TOOL_PATHS),
            "records": copy.deepcopy(FR0014_BOUNDARY_RECORDS),
        },
        "defects": [
            {
                "id": "FR0015-D01",
                "summary": (
                    "The epoch-15 cargo-deny Docker Action fetched mutable "
                    "Alpine packages and streamed a release archive into tar "
                    "without authenticating the archive digest."
                ),
                "prior_state": "PINNED_ACTION_COMMIT_WITH_UNVERIFIED_RUNTIME_INPUTS",
                "authority_produced": False,
            },
            {
                "id": "FR0015-D02",
                "summary": (
                    "cargo-deny frozen mode is offline and cannot initialize "
                    "an absent RustSec advisory database, so a cold runner "
                    "requires an independently pinned database snapshot."
                ),
                "required_state": (
                    "DIGEST_VERIFIED_SNAPSHOT_VALID_GIT_TREE_AND_OFFLINE_CHECK"
                ),
            },
        ],
        "correction": {
            "normative_qualification_evidence": [
                "SIGNED_FR_0014_ACTIVE_BOUNDARY_AND_LINEAR_SUCCESSORS",
                "FR_0015_R_MAIN_CI_RESULT_AND_GITHUB_OIDC_ATTESTATION",
                "FR_0015_R_MAIN_FORMAL_RESULT_AND_GITHUB_OIDC_ATTESTATION",
                "FR_0015_R_EXACT_LOCAL_VALIDATION",
                "SIGNED_SOURCE_AUTHORITY",
            ],
            "automated_paid_model_reviews": {
                "required": False,
                "normative": False,
                "authority_conferred": False,
                "reason": "NO_INDEPENDENTLY_ATTESTED_PROVIDER_PROVENANCE",
            },
            "hosted_result_transport": {
                "protocol": "HALDIR_EPOCH_16_HOSTED_RESULT_V1",
                "state": "EPOCH_16_PROVENANCE_FORMAT",
                "governance_epoch": 16,
                "authority_conferred": False,
            },
            "branch_protection_policy": {
                "capture_method": "GET_ONLY",
                "mutation_performed": False,
                "endpoint": ("repos/sepahead/haldir/branches/main/protection"),
                "expected_policy": copy.deepcopy(BRANCH_PROTECTION_EXPECTED_POLICY),
                "get_materializes_contexts_and_checks": True,
            },
            "branch_control_get": {
                "repository_identity": (
                    "EXACT_NONFORK_IDENTITY_WITH_ABSENT_PARENT_AND_SOURCE"
                ),
                "ruleset_update_rule": {"type": "update"},
                "omitted_update_parameter_reconstructed": False,
                "ruleset_history_and_version_required": True,
            },
            "run_attempt_chronology": {
                "attempt_created_vs_started_order_assumed": False,
                "attempt_created_and_started_bounds": (
                    "ORIGINAL_RUN_LIFETIME_AND_ATTEMPT_COMPLETION"
                ),
                "all_job_bounds": "ORIGINAL_RUN_LIFETIME",
                "critical_current_attempt_bounds": (
                    "ATTEMPT_STARTED_AT_THROUGH_ATTEMPT_UPDATED_AT"
                ),
                "ordinary_attempt_jobs": "EXACT_CANONICAL_EQUALITY",
            },
            "json_numeric_identity": (
                "SCHEMA_INTEGER_FIELDS_REQUIRE_EXACT_JSON_INTEGER_"
                "BOOLEAN_AND_FLOAT_REJECTED"
            ),
            "bounded_subprocess_pipes": (
                "PIPES_CLOSED_AND_LEADER_REAPED_ON_SUCCESS_TIMEOUT_BOUND_AND_ERROR"
            ),
            "bounded_subprocess_identity": (
                "WAITID_WNOWAIT_PROVEN_PRE_REAP_SIGNALING_"
                "NO_POST_REAP_PID_OR_PGID_SIGNALING"
            ),
            "trusted_root_bootstrap": {
                "path": TRUSTED_ROOT_PATH,
                "bytes": TRUSTED_ROOT_BYTES,
                "sha256": TRUSTED_ROOT_SHA256,
                "evidence_selected_root_allowed": False,
            },
            "offline_verifier_tool": {
                "name": "gh",
                "version": GH_CLI_VERSION,
                "linux_amd64_archive": GH_CLI_LINUX_AMD64_ARCHIVE,
                "linux_amd64_archive_sha256": GH_CLI_LINUX_AMD64_ARCHIVE_SHA256,
                "linux_amd64_archive_bytes": GH_CLI_LINUX_AMD64_ARCHIVE_BYTES,
                "linux_amd64_binary_sha256": GH_CLI_LINUX_AMD64_BINARY_SHA256,
                "linux_amd64_binary_bytes": GH_CLI_LINUX_AMD64_BINARY_BYTES,
                "macos_arm64_archive": GH_CLI_MACOS_ARM64_ARCHIVE,
                "macos_arm64_archive_sha256": GH_CLI_MACOS_ARM64_ARCHIVE_SHA256,
                "macos_arm64_archive_bytes": GH_CLI_MACOS_ARM64_ARCHIVE_BYTES,
                "macos_arm64_binary_sha256": GH_CLI_MACOS_ARM64_BINARY_SHA256,
                "macos_arm64_binary_bytes": GH_CLI_MACOS_ARM64_BINARY_BYTES,
                "linux_install": "DIGEST_VERIFIED_ARCHIVE_NO_CURL_TO_SHELL",
                "local_binary_admission": ("EXACT_PLATFORM_BINARY_SIZE_AND_SHA256"),
            },
            "ecosystem_pin_contract": {
                "fr0015_change_reason": (
                    "REPLACE_UNVERIFIED_DOCKER_ACTION_RUNTIME_INPUTS"
                ),
                "inherited_immutable_action_baseline": [
                    {
                        "name": "actions/setup-python",
                        "version": "v7.0.0",
                        "commit": "5fda3b95a4ea91299a34e894583c3862153e4b97",
                    },
                    {
                        "name": "actions/setup-java",
                        "version": "v5.6.0",
                        "commit": "03ad4de0992f5dab5e18fcb136590ce7c4a0ac95",
                    },
                    {
                        "name": "actions/attest",
                        "version": "v4.2.1",
                        "commit": "508db95dd578ae2727ebd6217d5ba78e4fbda05d",
                    },
                ],
                "cargo_deny_direct_execution": {
                    "version": "0.20.2",
                    "action_uses": 0,
                    "rustsec_repository_url": (
                        "https://github.com/RustSec/advisory-db"
                    ),
                    "rustsec_archive_url": (
                        "https://codeload.github.com/RustSec/advisory-db/tar.gz/"
                        "7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2"
                    ),
                    "rustsec_commit": ("7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2"),
                    "rustsec_committed_at": "2026-07-29T08:17:10-07:00",
                    "rustsec_tree": "2d3ab21e05f8b06ad2e232f92894b5e247d817ce",
                    "rustsec_archive_bytes": 441_027,
                    "rustsec_archive_sha256": (
                        "ab968b67150079bc386d098311cdab98e23745d555b3018837c91f3ae847967a"
                    ),
                    "maximum_staleness_days": 90,
                    "mode": (
                        "SAFE_BOUNDED_EXTRACT_EXACT_GIT_TREE_DIRECT_BINARY_"
                        "FROZEN_NETWORK_ISOLATED"
                    ),
                },
                "github_cli_security_advisory": "GHSA-8cg3-r6g9-fpg2",
            },
            "workflow_yaml_pin_scanner": (
                "USES_SAFE_SIMPLE_KEY_SUBSET_NO_COMPLEX_OR_FLOW_MAPPING_KEYS"
            ),
            "oidc_job_isolation": (
                "NO_CHECKOUT_NO_REPOSITORY_CODE_CANONICAL_MAIN_PUSH_ONLY"
            ),
            "data_record_modes": "REGULAR_100644_ONLY",
            "worktree_modes": ("GIT_EXECUTABLE_PARITY_AND_NO_GROUP_OR_WORLD_WRITE"),
        },
        "stage_contract": {
            "repair": {
                "subject": REPAIR_SUBJECT,
                "state_after": "PENDING_QUALIFICATION",
            },
            "qualification": {
                "subject": QUALIFICATION_SUBJECT,
                "namespace": QUALIFICATION_NAMESPACE,
                "data_only": True,
                "state_after": "QUALIFIED_PENDING_ACTIVATION",
                "statuses": dict(sorted(QUALIFICATION_STATUSES.items())),
            },
            "activation": {
                "subject": ACTIVATION_SUBJECT,
                "namespace": ACTIVATION_NAMESPACE,
                "data_only": True,
                "state_after": "ACTIVE",
                "statuses": dict(sorted(ACTIVATION_STATUSES.items())),
            },
            "ordinary_successor_before_activation": "REJECT",
        },
        "post_activation_contract": {
            "model": "SIGNED_LINEAR_SCOPED_MILESTONES",
            "threat_model": "TRUSTED_SOURCE_AUTHORITY_AND_OWNER_ACCOUNT",
            "writer_adversarial_immutability_claimed": False,
            "main_update_ruleset": {
                "name": MAIN_RULESET_NAME,
                "enforcement": "active",
                "sole_bypass_actor": {
                    "actor_type": "User",
                    "actor_id": MAIN_RULESET_OWNER_ID,
                    "bypass_mode": "always",
                },
                "scope": "refs/heads/main",
                "observed_get_rule": {"type": "update"},
                "omitted_update_parameter_reconstructed": False,
                "layers_with_classic_branch_protection": True,
            },
            "required_pre_accept_checks": [
                {"context": context, "app_id": GITHUB_ACTIONS_APP_ID}
                for context in sorted(REQUIRED_PRE_ACCEPT_CHECKS)
            ],
            "post_main_attestation_jobs": [
                "attest-ci-audit-result",
                "attest-formal-audit-result",
            ],
            "trust_root_paths_immutable": sorted(PROTECTED_AFTER_ACTIVATION),
            "recovery_namespace_prefixes_immutable": list(
                PROTECTED_RECOVERY_PREFIXES_AFTER_ACTIVATION
            ),
            "recovery_namespace_match": "UNICODE_CASEFOLD_PREFIX",
            "future_framework_recovery_epoch": (
                "REQUIRES_INTENTIONAL_SIGNED_GATE_AND_TRUST_ROOT_REPLACEMENT"
            ),
        },
        "authority": _authority("PENDING_QUALIFICATION"),
        "limitations": limitations,
    }


def _assert_absent(repo: Path, commit: str, paths: Sequence[str]) -> None:
    for path in paths:
        if _git(repo, "ls-tree", "-z", commit, "--", path, limit=64 * 1024):
            _fail("FR0015_LEGACY_COMPLETION_PRESENT:" + path)


def _verify_legacy_boundary(repo: Path) -> None:
    if _metadata(repo, PARENT)["tree"] != PARENT_TREE:
        _fail("FR0015_PARENT_TREE")
    if _metadata(repo, FR0014_REPAIR)["tree"] != FR0014_REPAIR_TREE:
        _fail("FR0015_FR0014_REPAIR_TREE")
    _verify_commit_identity(
        repo,
        FR0014_REPAIR,
        parent=FR0014_REPAIR_PARENT,
        subject=FR0014_REPAIR_SUBJECT,
    )
    if _metadata(repo, FR0014_QUALIFICATION)["tree"] != FR0014_QUALIFICATION_TREE:
        _fail("FR0015_FR0014_QUALIFICATION_TREE")
    _verify_commit_identity(
        repo,
        FR0014_QUALIFICATION,
        parent=FR0014_REPAIR,
        subject=FR0014_QUALIFICATION_SUBJECT,
    )
    if _metadata(repo, FR0014_ACTIVATION)["tree"] != FR0014_ACTIVATION_TREE:
        _fail("FR0015_FR0014_ACTIVATION_TREE")
    _verify_commit_identity(
        repo,
        FR0014_ACTIVATION,
        parent=FR0014_QUALIFICATION,
        subject=FR0014_ACTIVATION_SUBJECT,
    )
    legacy_protected = {
        ".github/workflows/ci.yml",
        ".github/workflows/formal.yml",
        "tools/verify-ci-pins.py",
        "tools/release/current-audit-gate.sh",
        "tools/release/sigstore-public-good-trusted-root.jsonl",
        "release/0.9.0/allowed-signers",
        "tools/release/verify-current-audit.py",
        "tools/release/test_verify_current_audit_fr_0009.py",
        *FR0014_BOUNDARY_RECORDS,
        *HISTORICAL_RECOVERY_TOOL_PATHS,
    }
    for commit, parent, tree, subject in FR0014_SUCCESSORS:
        if _metadata(repo, commit)["tree"] != tree:
            _fail("FR0015_FR0014_SUCCESSOR_TREE:" + commit)
        _verify_commit_identity(repo, commit, parent=parent, subject=subject)
        statuses = _changed_statuses(repo, parent, commit)
        if (
            not statuses
            or len(statuses) > MAX_SUCCESSOR_PATHS
            or any(
                path in legacy_protected
                or any(
                    path.casefold().startswith(prefix.casefold())
                    for prefix in PROTECTED_RECOVERY_PREFIXES_AFTER_ACTIVATION
                )
                for path in statuses
            )
        ):
            _fail("FR0015_FR0014_SUCCESSOR_SCOPE:" + commit)
    for path, expected in FR0014_BOUNDARY_RECORDS.items():
        observed = file_record(repo, PARENT, path)
        comparable = {
            key: observed[key]
            for key in ("git_mode", "git_object_id", "sha256", "bytes")
        }
        if comparable != expected:
            _fail("FR0015_LEGACY_RECORD:" + path)
    _assert_absent(
        repo,
        PARENT,
        sorted(
            FR0013_FORBIDDEN_COMPLETION_PATHS
            | FR0010_FORBIDDEN_COMPLETION_PATHS
            | FR0011_FORBIDDEN_COMPLETION_PATHS
            | FR0012_FORBIDDEN_COMPLETION_PATHS
        ),
    )
    plan, _payload = _read_json(repo, PARENT, FR0014_PLAN_PATH)
    if (
        plan.get("recovery_id") != "FR-0014"
        or plan.get("protocol_parent", {}).get("commit") != FR0014_REPAIR_PARENT
        or plan.get("repair_identity", {}).get("commit")
        != "SIGNED_COMMIT_CONTAINING_THIS_PLAN"
    ):
        _fail("FR0015_FR0014_PLAN_STATE")
    _validate_authority(
        plan.get("authority"),
        state="PENDING_QUALIFICATION",
        framework_epoch=15,
    )
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in plan.items()
        if key != "detached_signature"
    }
    _verify_detached(
        repo,
        plan.get("detached_signature"),
        canonical_json_bytes(unsigned),
        namespace=FR0014_PLAN_NAMESPACE,
    )
    qualification, _payload = _read_json(
        repo,
        PARENT,
        FR0014_QUALIFICATION_PATH,
    )
    if (
        qualification.get("recovery_id") != "FR-0014"
        or qualification.get("stage") != "QUALIFICATION"
        or qualification.get("state_before") != "PENDING_QUALIFICATION"
        or qualification.get("state_after") != "QUALIFIED_PENDING_ACTIVATION"
        or qualification.get("repair_commit") != FR0014_REPAIR
        or qualification.get("plan_record")
        != file_record(repo, PARENT, FR0014_PLAN_PATH)
    ):
        _fail("FR0015_FR0014_QUALIFICATION_STATE")
    _validate_authority(
        qualification.get("authority"),
        state="QUALIFIED_PENDING_ACTIVATION",
        framework_epoch=15,
    )
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in qualification.items()
        if key != "detached_signature"
    }
    _verify_detached(
        repo,
        qualification.get("detached_signature"),
        canonical_json_bytes(unsigned),
        namespace=FR0014_QUALIFICATION_NAMESPACE,
    )
    activation, _payload = _read_json(repo, PARENT, FR0014_ACTIVATION_PATH)
    if (
        activation.get("recovery_id") != "FR-0014"
        or activation.get("stage") != "ACTIVATION"
        or activation.get("state_before") != "QUALIFIED_PENDING_ACTIVATION"
        or activation.get("state_after") != "ACTIVE"
        or activation.get("repair_commit") != FR0014_REPAIR
        or activation.get("qualification_commit") != FR0014_QUALIFICATION
        or activation.get("plan_record") != file_record(repo, PARENT, FR0014_PLAN_PATH)
        or activation.get("qualification_record")
        != file_record(repo, PARENT, FR0014_QUALIFICATION_PATH)
    ):
        _fail("FR0015_FR0014_ACTIVATION_STATE")
    _validate_authority(
        activation.get("authority"),
        state="ACTIVE",
        framework_epoch=15,
    )
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in activation.items()
        if key != "detached_signature"
    }
    _verify_detached(
        repo,
        activation.get("detached_signature"),
        canonical_json_bytes(unsigned),
        namespace=FR0014_ACTIVATION_NAMESPACE,
    )


def _verify_repair_tree(repo: Path, commit: str) -> None:
    if _changed_statuses(repo, PARENT, commit) != dict(sorted(REPAIR_STATUSES.items())):
        _fail("FR0015_REPAIR_DIFF")
    for path, mode in REPAIR_MODES.items():
        if _tree_entry(repo, commit, path)["mode"] != mode:
            _fail("FR0015_REPAIR_MODE:" + path)
    for path in FR0014_BOUNDARY_RECORDS:
        if path not in REPAIR_STATUSES and _tree_entry(
            repo, commit, path
        ) != _tree_entry(repo, PARENT, path):
            _fail("FR0015_LEGACY_DRIFT:" + path)
    _assert_absent(
        repo,
        commit,
        sorted(
            FR0013_FORBIDDEN_COMPLETION_PATHS
            | FR0010_FORBIDDEN_COMPLETION_PATHS
            | FR0011_FORBIDDEN_COMPLETION_PATHS
            | FR0012_FORBIDDEN_COMPLETION_PATHS
        ),
    )


def _verify_repair(repo: Path, commit: str) -> dict[str, Any]:
    _verify_commit_identity(repo, commit, parent=PARENT, subject=REPAIR_SUBJECT)
    _verify_repair_tree(repo, commit)
    value, _payload = _read_json(repo, commit, PLAN_PATH)
    expected = expected_plan(repo, commit)
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "detached_signature"
    }
    if set(value) != {*expected, "detached_signature"} or unsigned != expected:
        _fail("FR0015_PLAN_INVALID")
    _validate_authority(
        value.get("authority"),
        state="PENDING_QUALIFICATION",
    )
    _verify_detached(
        repo,
        value["detached_signature"],
        canonical_json_bytes(unsigned),
        namespace=PLAN_NAMESPACE,
    )
    return value


def _load_protocol_module(repo: Path, repair_commit: str) -> ModuleType:
    payload = _file(repo, repair_commit, MODULE_PATH, MAX_GIT_BYTES)
    try:
        current = (repo / MODULE_PATH).read_bytes()
    except OSError:
        _fail("FR0015_MODULE_WORKTREE_DRIFT")
    if current != payload:
        _fail("FR0015_MODULE_WORKTREE_DRIFT")
    specification = importlib.util.spec_from_file_location(
        "_haldir_fr0015_protocol", repo / MODULE_PATH
    )
    if specification is None or specification.loader is None:
        _fail("FR0015_MODULE_LOAD")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    if (
        module.RESULT_PROTOCOL != "HALDIR_EPOCH_16_HOSTED_RESULT_V1"
        or module.MAX_EPOCH16_RUN_ATTEMPT != 8
    ):
        _fail("FR0015_MODULE_CONTRACT")
    return module


def _evidence_catalog(
    repo: Path, commit: str, paths: Sequence[str]
) -> list[dict[str, Any]]:
    return [file_record(repo, commit, path) for path in paths]


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("FR0015_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("FR0015_TIMESTAMP:" + label)
    if parsed.tzinfo != timezone.utc:
        _fail("FR0015_TIMESTAMP:" + label)
    return parsed


def _parse_git_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        _fail("FR0015_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _fail("FR0015_TIMESTAMP:" + label)
    if parsed.tzinfo is None:
        _fail("FR0015_TIMESTAMP:" + label)
    return parsed.astimezone(timezone.utc)


def _bounded_file_sha256(path: Path, *, expected_bytes: int) -> str:
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > expected_bytes:
                _fail("FR0015_GH_EXECUTABLE")
            digest.update(chunk)
    if consumed != expected_bytes:
        _fail("FR0015_GH_EXECUTABLE")
    return digest.hexdigest()


def _trusted_gh() -> tuple[Path, str]:
    if sys.platform == "darwin":
        expected_binary_bytes = GH_CLI_MACOS_ARM64_BINARY_BYTES
        expected_binary_sha256 = GH_CLI_MACOS_ARM64_BINARY_SHA256
    elif sys.platform.startswith("linux"):
        expected_binary_bytes = GH_CLI_LINUX_AMD64_BINARY_BYTES
        expected_binary_sha256 = GH_CLI_LINUX_AMD64_BINARY_SHA256
    else:
        _fail("FR0015_GH_EXECUTABLE")
    configured = os.environ.get("HALDIR_FR0015_GH")
    if configured is not None:
        if sys.platform.startswith("linux"):
            runner_temp = os.environ.get("RUNNER_TEMP")
            expected = (
                Path(runner_temp)
                / "haldir-gh-2.96.0"
                / "gh_2.96.0_linux_amd64"
                / "bin"
                / "gh"
                if runner_temp
                else None
            )
            if expected is None or configured != str(expected):
                _fail("FR0015_GH_EXECUTABLE")
        candidates = (Path(configured),)
    else:
        candidates = (
            Path("/usr/bin/gh"),
            Path("/usr/local/bin/gh"),
            Path("/opt/homebrew/bin/gh"),
        )
    executable: Path | None = None
    for candidate in candidates:
        try:
            if configured is not None and candidate.is_symlink():
                continue
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not os.access(resolved, os.X_OK)
        ):
            continue
        if (
            metadata.st_size != expected_binary_bytes
            or _bounded_file_sha256(
                resolved,
                expected_bytes=expected_binary_bytes,
            )
            != expected_binary_sha256
        ):
            continue
        executable = resolved
        break
    if executable is None:
        _fail("FR0015_GH_EXECUTABLE")
    with tempfile.TemporaryDirectory(prefix="haldir-fr0015-gh-version-") as name:
        completed = subprocess.run(
            (str(executable), "--version"),
            env={
                "GH_CONFIG_DIR": name,
                "HOME": name,
                "LC_ALL": "C",
                "PATH": f"{executable.parent}:/usr/bin:/bin",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 4096:
        _fail("FR0015_GH_VERSION")
    try:
        output = completed.stdout.decode("ascii")
    except UnicodeDecodeError:
        _fail("FR0015_GH_VERSION")
    if not output.startswith("gh version 2.96.0 (2026-07-02)\n"):
        _fail("FR0015_GH_VERSION")
    return executable, output.rstrip("\n")


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                _fail("FR0015_TEMP_WRITE")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _kill_process_group(
    process: subprocess.Popen[bytes],
    *,
    zombie_leader: bool = False,
) -> bool:
    """Signal a group whose leader is already proven to be an unreaped child."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except PermissionError:
        # macOS reports EPERM for a process group containing only its
        # already-exited, deliberately unreaped leader. Same-UID live
        # descendants remain signalable, so this is success only at that
        # identity-anchored point.
        return zombie_leader
    except OSError:
        return False
    return True


def _close_pipe(pipe: BinaryIO | None) -> bool:
    if pipe is not None:
        try:
            pipe.close()
        except Exception:
            return False
    return True


def _close_pipe_with_fallback(pipe: BinaryIO | None) -> bool:
    """Report helper failure while still making a direct close attempt."""

    try:
        helper_ok = _close_pipe(pipe)
    except BaseException:
        helper_ok = False
    if pipe is not None and not pipe.closed:
        try:
            pipe.close()
        except BaseException:
            return False
    return helper_ok


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> bool:
    """Kill the whole session, fall back to the leader, and reap it."""

    try:
        zombie_leader = _leader_exited_unreaped(process)
    except OSError:
        # ECHILD (or any inability to prove retained child identity) means
        # the numeric PID/PGID may already be reusable. Never signal it.
        return False
    cleanup_ok = _kill_process_group(
        process,
        zombie_leader=zombie_leader,
    )
    if not cleanup_ok:
        try:
            _leader_exited_unreaped(process)
        except OSError:
            return False
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError:
            cleanup_ok = False
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            zombie_leader = _leader_exited_unreaped(process)
        except OSError:
            return False
        cleanup_ok = (
            _kill_process_group(
                process,
                zombie_leader=zombie_leader,
            )
            and cleanup_ok
        )
        try:
            _leader_exited_unreaped(process)
        except OSError:
            return False
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError:
            cleanup_ok = False
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_ok = False
    except OSError:
        # wait(2) may have released or lost the child identity. Retrying a
        # signal using only its former numeric identifiers is forbidden.
        cleanup_ok = False
    return cleanup_ok


def _emergency_terminate_and_reap(process: subprocess.Popen[bytes]) -> bool:
    """Best-effort cleanup that does not call overridable cleanup helpers."""

    try:
        os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOWAIT | os.WNOHANG,
        )
    except OSError:
        # An emergency path may be entered after an arbitrary helper failure,
        # including one after reap. Do not signal without retained identity.
        return False
    cleanup_ok = True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException:
        cleanup_ok = False
    try:
        os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOWAIT | os.WNOHANG,
        )
    except OSError:
        return False
    try:
        process.kill()
    except ProcessLookupError:
        pass
    except BaseException:
        cleanup_ok = False
    try:
        process.wait(timeout=5)
    except BaseException:
        cleanup_ok = False
    return cleanup_ok


def _reap_signaled_leader(process: subprocess.Popen[bytes]) -> bool:
    """Reap a leader whose identity-anchored process group was already killed."""

    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def _leader_exited_unreaped(process: subprocess.Popen[bytes]) -> bool:
    """Observe leader exit without releasing its PID/process-group identity."""

    status = os.waitid(
        os.P_PID,
        process.pid,
        os.WEXITED | os.WNOWAIT | os.WNOHANG,
    )
    return status is not None


def _run_bounded(
    command: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    output_limit: int,
) -> tuple[int, bytes, bytes]:
    """Run one process group with exact bounds and leader/pipe cleanup."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or type(output_limit) is not int
        or output_limit < 0
    ):
        _fail("FR0015_PROCESS_BOUND")
    selector: selectors.BaseSelector | None = None
    process: subprocess.Popen[bytes] | None = None
    stdout_pipe: BinaryIO | None = None
    stderr_pipe: BinaryIO | None = None
    streams: dict[str, bytearray] | None = None
    deadline = 0.0
    failure: str | None = None
    returncode: int | None = None
    unexpected: BaseException | None = None
    consumed = 0
    leader_exited = False
    group_signaled = False
    pipe_cleanup_deadline: float | None = None
    pre_cleanup_ok = True
    try:
        selector = selectors.DefaultSelector()
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout_seconds
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
        stdout_pipe = process.stdout
        stderr_pipe = process.stderr
        if stdout_pipe is None or stderr_pipe is None:
            failure = "FR0015_PROCESS_PIPE"
        else:
            selector.register(stdout_pipe, selectors.EVENT_READ, "stdout")
            selector.register(stderr_pipe, selectors.EVENT_READ, "stderr")
            while selector.get_map() and failure is None:
                active_deadline = (
                    pipe_cleanup_deadline
                    if pipe_cleanup_deadline is not None
                    else deadline
                )
                remaining_time = active_deadline - time.monotonic()
                if remaining_time <= 0:
                    failure = (
                        "FR0015_PROCESS_CLEANUP"
                        if leader_exited
                        else "FR0015_PROCESS_TIMEOUT"
                    )
                    break
                ready = selector.select(min(remaining_time, 0.01))
                for key, _mask in ready:
                    remaining_bytes = output_limit - consumed
                    read_size = min(64 * 1024, remaining_bytes + 1)
                    chunk = os.read(key.fileobj.fileno(), max(1, read_size))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    streams[key.data].extend(chunk)
                    consumed += len(chunk)
                    if consumed > output_limit:
                        failure = "FR0015_PROCESS_OUTPUT_BOUND"
                        break
                if not leader_exited and _leader_exited_unreaped(process):
                    leader_exited = True
                    signal_ok = _kill_process_group(
                        process,
                        zombie_leader=True,
                    )
                    group_signaled = True
                    pre_cleanup_ok = signal_ok and pre_cleanup_ok
                    pipe_cleanup_deadline = min(
                        deadline,
                        time.monotonic() + 1,
                    )
            while not leader_exited and failure is None:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    failure = "FR0015_PROCESS_TIMEOUT"
                    break
                if _leader_exited_unreaped(process):
                    leader_exited = True
                    break
                time.sleep(min(remaining_time, 0.01))
            if failure is None and leader_exited:
                if not group_signaled:
                    signal_ok = _kill_process_group(
                        process,
                        zombie_leader=True,
                    )
                    group_signaled = True
                    pre_cleanup_ok = signal_ok and pre_cleanup_ok
                try:
                    returncode = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    failure = "FR0015_PROCESS_REAP"
    except Exception:
        failure = "FR0015_PROCESS_CLEANUP"
    except BaseException as error:
        unexpected = error
    finally:
        cleanup_ok = pre_cleanup_ok
        try:
            if process is not None and (
                failure is not None or unexpected is not None or returncode is None
            ):
                try:
                    if group_signaled and pre_cleanup_ok:
                        cleanup_ok = _reap_signaled_leader(process) and cleanup_ok
                    else:
                        cleanup_ok = _terminate_and_reap(process) and cleanup_ok
                except BaseException:
                    cleanup_ok = False
                    try:
                        _emergency_terminate_and_reap(process)
                    except BaseException:
                        pass
        except BaseException:
            cleanup_ok = False
        finally:
            if selector is not None:
                try:
                    selector.close()
                except BaseException:
                    cleanup_ok = False
            try:
                cleanup_ok = _close_pipe_with_fallback(stdout_pipe) and cleanup_ok
            except BaseException:
                cleanup_ok = False
            try:
                cleanup_ok = _close_pipe_with_fallback(stderr_pipe) and cleanup_ok
            except BaseException:
                cleanup_ok = False
    if not cleanup_ok:
        _fail("FR0015_PROCESS_CLEANUP")
    if unexpected is not None:
        raise unexpected
    if failure is not None:
        _fail(failure)
    if returncode is None or streams is None:
        _fail("FR0015_PROCESS_REAP")
    return returncode, bytes(streams["stdout"]), bytes(streams["stderr"])


def _validate_trusted_root(payload: bytes) -> None:
    if (
        len(payload) != TRUSTED_ROOT_BYTES
        or hashlib.sha256(payload).hexdigest() != TRUSTED_ROOT_SHA256
        or b"\0" in payload
        or not payload.endswith(b"\n")
    ):
        _fail("FR0015_TRUSTED_ROOT_BOUND")
    lines = payload.splitlines()
    if len(lines) != 1:
        _fail("FR0015_TRUSTED_ROOT_BOUND")
    try:
        value = json.loads(lines[0])
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0015_TRUSTED_ROOT_JSONL")
    if (
        not isinstance(value, dict)
        or value.get("mediaType")
        != "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
        or {
            item.get("uri")
            for item in value.get("certificateAuthorities", [])
            if isinstance(item, dict)
        }
        != {"https://fulcio.sigstore.dev"}
        or {
            item.get("baseUrl")
            for item in value.get("tlogs", [])
            if isinstance(item, dict)
        }
        != {
            "https://rekor.sigstore.dev",
            "https://log2025-1.rekor.sigstore.dev",
        }
    ):
        _fail("FR0015_TRUSTED_ROOT_IDENTITY")


def _verification_argv(
    *,
    executable: Path,
    result_path: Path,
    bundle_path: Path,
    trusted_root_path: Path,
    workflow: str,
    subject_commit: str,
) -> tuple[str, ...]:
    workflow_path = CI_WORKFLOW_PATH if workflow == "ci" else FORMAL_WORKFLOW_PATH
    identity = f"https://github.com/sepahead/haldir/{workflow_path}@refs/heads/main"
    return (
        str(executable),
        "attestation",
        "verify",
        str(result_path),
        "--bundle",
        str(bundle_path),
        "--custom-trusted-root",
        str(trusted_root_path),
        "--repo",
        "sepahead/haldir",
        "--format",
        "json",
        "--cert-identity",
        identity,
        "--cert-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--deny-self-hosted-runners",
        "--digest-alg",
        "sha256",
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
        "--signer-digest",
        subject_commit,
        "--source-digest",
        subject_commit,
        "--source-ref",
        "refs/heads/main",
        "--hostname",
        "github.com",
    )


def _offline_verification_environment(
    *,
    executable: Path,
    root: Path,
    config_dir: Path,
) -> dict[str, str]:
    return {
        "ALL_PROXY": "http://127.0.0.1:1",
        "GH_CONFIG_DIR": str(config_dir),
        "GH_HOST": "github.com",
        "GH_TOKEN": "invalid-offline-token",
        "GITHUB_TOKEN": "invalid-offline-token",
        "HOME": str(root),
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "HTTP_PROXY": "http://127.0.0.1:1",
        "LC_ALL": "C",
        "NO_PROXY": "",
        "PATH": f"{executable.parent}:/usr/bin:/bin",
        "TZ": "UTC",
    }


def _verify_attestation_offline(
    *,
    result_payload: bytes,
    bundle_payload: bytes,
    trusted_root_payload: bytes,
    workflow: str,
    subject_commit: str,
    attempt: int,
) -> tuple[Any, dict[str, Any]]:
    _validate_trusted_root(trusted_root_payload)
    executable, version = _trusted_gh()
    with tempfile.TemporaryDirectory(prefix="haldir-fr0015-attestation-") as name:
        root = Path(name)
        result_path = root / f"epoch-16-{workflow}-result-attempt-{attempt}.json"
        bundle_path = root / "attestation.jsonl"
        trusted_root_path = root / "trusted-root.jsonl"
        _write_private(result_path, result_payload)
        _write_private(bundle_path, bundle_payload)
        _write_private(trusted_root_path, trusted_root_payload)
        command = _verification_argv(
            executable=executable,
            result_path=result_path,
            bundle_path=bundle_path,
            trusted_root_path=trusted_root_path,
            workflow=workflow,
            subject_commit=subject_commit,
        )
        config_dir = root / "gh-config"
        config_dir.mkdir(mode=0o700)
        environment = _offline_verification_environment(
            executable=executable,
            root=root,
            config_dir=config_dir,
        )
        returncode, stdout, stderr = _run_bounded(
            command,
            cwd=root,
            env=environment,
            timeout_seconds=30,
            output_limit=2 * 1024 * 1024,
        )
    if returncode != 0 or stderr:
        _fail("FR0015_ATTESTATION_CRYPTOGRAPHY")
    try:
        receipt = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0015_ATTESTATION_CRYPTOGRAPHY")
    return receipt, {
        "tool": "gh",
        "version": version,
        "network_mode": "OFFLINE_INVALID_PROXY_AND_TOKEN",
        "custom_trusted_root_sha256": hashlib.sha256(trusted_root_payload).hexdigest(),
        "result": "PASS",
    }


def _hosted_commands(
    *,
    workflow: str,
    run_id: int,
    attempt: int,
    artifact_id: int,
) -> dict[str, str]:
    fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "number,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    attempt_fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "number,startedAt,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    artifact_name = f"epoch-16-{workflow}-result-attempt-{attempt}.json"
    return {
        "ordinary": (f"gh run view {run_id} --repo sepahead/haldir --json {fields}"),
        "attempt": (
            f"gh run view {run_id} --repo sepahead/haldir --attempt {attempt} "
            f"--json {attempt_fields}"
        ),
        "artifact_list": (
            "gh api --method GET "
            f"repos/sepahead/haldir/actions/runs/{run_id}/artifacts"
            f"?name={artifact_name}&per_page=100"
        ),
        "artifact_get": (
            f"gh api --method GET repos/sepahead/haldir/actions/artifacts/{artifact_id}"
        ),
        "artifact_download": (
            "gh api --method GET "
            f"repos/sepahead/haldir/actions/artifacts/{artifact_id}/zip"
        ),
        "attestation_download": (
            f"gh attestation download {artifact_name} "
            "--repo sepahead/haldir --limit 1 "
            "--predicate-type https://slsa.dev/provenance/v1"
        ),
    }


def _validate_hosted_lane(
    repo: Path,
    containing_commit: str,
    *,
    repair_commit: str,
    workflow: str,
    subject_commit: str,
    paths: tuple[str, str, str],
    protocol: ModuleType,
) -> dict[str, Any]:
    capture, _capture_payload = _read_json(repo, containing_commit, paths[0])
    result_payload = _file(repo, containing_commit, paths[1], 256 * 1024)
    bundle_payload = _file(repo, containing_commit, paths[2], 1024 * 1024)
    trusted_root_payload = _file(
        repo,
        repair_commit,
        TRUSTED_ROOT_PATH,
        MAX_TRUSTED_ROOT_BYTES,
    )
    required = {
        "schema_version",
        "protocol",
        "workflow",
        "subject_commit",
        "subject_tree",
        "expected_ref",
        "ordinary",
        "attempt_metadata",
        "artifact_listing",
        "artifact_by_id",
        "artifact",
        "artifact_download",
        "commands",
        "capture_tool",
        "result_record",
        "attestation_record",
        "trusted_root_record",
        "attestation_verification",
        "capture_verification",
        "captured_at_utc",
        "result",
    }
    if (
        not isinstance(capture, dict)
        or set(capture) != required
        or capture["schema_version"] != "1.0.0"
        or capture["protocol"] != "HALDIR_FR_0015_HOSTED_RESULT_CAPTURE_V1"
        or capture["workflow"] != workflow
        or capture["subject_commit"] != subject_commit
        or capture["subject_tree"] != _metadata(repo, subject_commit)["tree"]
        or capture["expected_ref"] != "refs/heads/main"
        or capture["result"] != "PASS"
        or capture["capture_tool"] != file_record(repo, repair_commit, CAPTURE_PATH)
    ):
        _fail("FR0015_HOSTED_CAPTURE_SCHEMA")
    if capture["result_record"] != file_record(repo, containing_commit, paths[1]):
        _fail("FR0015_HOSTED_RESULT_RECORD")
    if capture["attestation_record"] != file_record(repo, containing_commit, paths[2]):
        _fail("FR0015_HOSTED_ATTESTATION_RECORD")
    if capture["trusted_root_record"] != file_record(
        repo, repair_commit, TRUSTED_ROOT_PATH
    ):
        _fail("FR0015_HOSTED_TRUSTED_ROOT_RECORD")
    _validate_trusted_root(trusted_root_payload)
    run = protocol.validate_epoch16_run_documents(
        capture["ordinary"],
        capture["attempt_metadata"],
        workflow=workflow,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
    )
    listing = capture["artifact_listing"]
    listed_artifact = protocol.validate_artifact_listing(listing)
    if (
        listed_artifact != capture["artifact"]
        or capture["artifact_by_id"] != capture["artifact"]
    ):
        _fail("FR0015_ARTIFACT_UNIQUENESS")
    if capture["artifact_download"] != {
        "bytes": len(result_payload),
        "content_mode": "DIRECT_UNARCHIVED_FILE",
        "sha256": hashlib.sha256(result_payload).hexdigest(),
    }:
        _fail("FR0015_ARTIFACT_DOWNLOAD")
    artifact = capture["artifact"]
    artifact_id = artifact.get("id", 0) if isinstance(artifact, dict) else 0
    if capture["commands"] != _hosted_commands(
        workflow=workflow,
        run_id=run["run_id"],
        attempt=run["attempt"],
        artifact_id=artifact_id,
    ):
        _fail("FR0015_HOSTED_COMMANDS")
    captured = _parse_utc(capture["captured_at_utc"], "hosted.captured")
    if captured < max(
        _parse_utc(capture["ordinary"]["updatedAt"], "hosted.run.updated"),
        _parse_utc(
            capture["attempt_metadata"]["updatedAt"],
            "hosted.attempt.updated",
        ),
        _parse_utc(capture["artifact"]["updated_at"], "hosted.artifact.updated"),
    ) or captured > _parse_git_time(
        _metadata(repo, containing_commit)["committer_date"],
        "hosted.containing_commit",
    ):
        _fail("FR0015_HOSTED_CHRONOLOGY")
    materials = [
        file_record(repo, subject_commit, path)
        for path in protocol.RESULT_CONTRACT[workflow]["material_paths"]
    ]
    protocol.validate_result_artifact(
        result_payload,
        workflow=workflow,
        subject_commit=subject_commit,
        subject_tree=capture["subject_tree"],
        run_id=run["run_id"],
        attempt=run["attempt"],
        run_number=run["run_number"],
        expected_ref="refs/heads/main",
        expected_materials=materials,
    )
    protocol.validate_artifact_metadata(
        capture["artifact"],
        workflow=workflow,
        run_id=run["run_id"],
        attempt=run["attempt"],
        subject_commit=subject_commit,
        result_payload=result_payload,
        producer_started=run["jobs"][protocol.RESULT_CONTRACT[workflow]["job"]][
            "started"
        ],
        producer_completed=run["jobs"][protocol.RESULT_CONTRACT[workflow]["job"]][
            "completed"
        ],
        attestation_started=run["jobs"][run["attestation_job"]]["started"],
    )
    captured_attestation = protocol.validate_attestation_evidence(
        bundle_payload,
        capture["attestation_verification"],
        workflow=workflow,
        result_payload=result_payload,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
        run_id=run["run_id"],
        attempt=run["attempt"],
        attestation_started=run["jobs"][run["attestation_job"]]["started"],
        attestation_completed=run["jobs"][run["attestation_job"]]["completed"],
    )
    live_receipt, offline_verification = _verify_attestation_offline(
        result_payload=result_payload,
        bundle_payload=bundle_payload,
        trusted_root_payload=trusted_root_payload,
        workflow=workflow,
        subject_commit=subject_commit,
        attempt=run["attempt"],
    )
    attestation = protocol.validate_attestation_evidence(
        bundle_payload,
        live_receipt,
        workflow=workflow,
        result_payload=result_payload,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
        run_id=run["run_id"],
        attempt=run["attempt"],
        attestation_started=run["jobs"][run["attestation_job"]]["started"],
        attestation_completed=run["jobs"][run["attestation_job"]]["completed"],
    )
    verification = capture["capture_verification"]
    if (
        not isinstance(verification, dict)
        or set(verification)
        != {
            "custom_trusted_root_sha256",
            "network_mode",
            "result",
            "tool",
            "version",
        }
        or verification["tool"] != "gh"
        or verification["version"] != offline_verification["version"]
        or verification["network_mode"] != "OFFLINE_INVALID_PROXY_AND_TOKEN"
        or verification["custom_trusted_root_sha256"]
        != hashlib.sha256(trusted_root_payload).hexdigest()
        or verification["result"] != "PASS"
        or captured_attestation != attestation
    ):
        _fail("FR0015_CAPTURE_OFFLINE_VERIFICATION")
    return {
        "workflow": workflow,
        "run_id": run["run_id"],
        "attempt": run["attempt"],
        "artifact_id": artifact_id,
        "result_sha256": hashlib.sha256(result_payload).hexdigest(),
        "attestation": attestation,
        "offline_verification": offline_verification,
    }


def _verify_stage_signature(
    repo: Path,
    value: dict[str, Any],
    *,
    namespace: str,
) -> dict[str, Any]:
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "detached_signature"
    }
    _verify_detached(
        repo,
        value.get("detached_signature"),
        canonical_json_bytes(unsigned),
        namespace=namespace,
    )
    return unsigned


def validate_repository_identity(value: Any) -> dict[str, Any]:
    """Validate the normalized identity of the exact non-fork repository."""

    expected = {
        "id": REPOSITORY_ID,
        "name": REPOSITORY_NAME,
        "full_name": REPOSITORY_FULL_NAME,
        "default_branch": REPOSITORY_DEFAULT_BRANCH,
        "fork": False,
        "owner": {
            "id": MAIN_RULESET_OWNER_ID,
            "login": REPOSITORY_OWNER_LOGIN,
            "type": "User",
        },
        "has_parent": False,
        "has_source": False,
    }
    if (
        not isinstance(value, dict)
        or set(value) != set(expected)
        or type(value.get("id")) is not int
        or type(value.get("fork")) is not bool
        or type(value.get("has_parent")) is not bool
        or type(value.get("has_source")) is not bool
        or not isinstance(value.get("owner"), dict)
        or set(value["owner"]) != {"id", "login", "type"}
        or type(value["owner"].get("id")) is not int
        or value != expected
    ):
        _fail("FR0015_REPOSITORY_IDENTITY")
    return copy.deepcopy(value)


def _parse_api_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        _fail("FR0015_API_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("FR0015_API_TIMESTAMP:" + label)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("FR0015_API_TIMESTAMP:" + label)
    return parsed


def validate_main_writer_ruleset(
    repository: Any,
    ruleset_list: Any,
    ruleset_by_id: Any,
    effective_rules: Any,
    ruleset_history: Any,
    ruleset_version: Any,
) -> dict[str, Any]:
    """Validate the exact owner-only update layer and its sole history version."""

    identity = validate_repository_identity(repository)
    if (
        not isinstance(ruleset_list, list)
        or len(ruleset_list) != 1
        or not isinstance(ruleset_list[0], dict)
        or not isinstance(ruleset_by_id, dict)
        or not isinstance(effective_rules, list)
        or not isinstance(ruleset_history, list)
        or not isinstance(ruleset_version, dict)
    ):
        _fail("FR0015_RULESET_SCHEMA")
    summary = ruleset_list[0]
    summary_fields = {
        "_links",
        "created_at",
        "enforcement",
        "id",
        "name",
        "node_id",
        "source",
        "source_type",
        "target",
        "updated_at",
    }
    ruleset_id = summary.get("id")
    if (
        set(summary) != summary_fields
        or type(ruleset_id) is not int
        or ruleset_id < 1
        or not isinstance(summary.get("node_id"), str)
        or not summary["node_id"]
    ):
        _fail("FR0015_RULESET_SUMMARY")
    api_url = (
        f"https://api.github.com/repos/{identity['full_name']}/rulesets/{ruleset_id}"
    )
    html_url = f"https://github.com/{identity['full_name']}/rules/{ruleset_id}"
    common = {
        "id": ruleset_id,
        "name": MAIN_RULESET_NAME,
        "target": "branch",
        "source_type": "Repository",
        "source": identity["full_name"],
        "enforcement": "active",
        "node_id": summary["node_id"],
        "_links": {
            "self": {"href": api_url},
            "html": {"href": html_url},
        },
        "created_at": summary.get("created_at"),
        "updated_at": summary.get("updated_at"),
    }
    if summary != common:
        _fail("FR0015_RULESET_SUMMARY")
    created = _parse_api_timestamp(summary["created_at"], "ruleset.created")
    updated = _parse_api_timestamp(summary["updated_at"], "ruleset.updated")
    if created > updated:
        _fail("FR0015_RULESET_CHRONOLOGY")
    bypass_actors = [
        {
            "actor_id": identity["owner"]["id"],
            "actor_type": identity["owner"]["type"],
            "bypass_mode": "always",
        }
    ]
    conditions = {
        "ref_name": {
            "exclude": [],
            "include": [f"refs/heads/{identity['default_branch']}"],
        }
    }
    observed_rule = {"type": "update"}
    expected_detail = {
        **common,
        "conditions": conditions,
        "rules": [observed_rule],
        "bypass_actors": bypass_actors,
        "current_user_can_bypass": "always",
    }
    if (
        set(ruleset_by_id) != set(expected_detail)
        or type(ruleset_by_id.get("id")) is not int
        or not isinstance(ruleset_by_id.get("rules"), list)
        or not isinstance(ruleset_by_id.get("bypass_actors"), list)
        or len(ruleset_by_id["bypass_actors"]) != 1
        or not isinstance(ruleset_by_id["bypass_actors"][0], dict)
        or type(ruleset_by_id["bypass_actors"][0].get("actor_id")) is not int
        or ruleset_by_id != expected_detail
    ):
        _fail("FR0015_RULESET_DETAIL")
    expected_effective = [
        {
            "type": "update",
            "ruleset_source_type": "Repository",
            "ruleset_source": identity["full_name"],
            "ruleset_id": ruleset_id,
        }
    ]
    if (
        len(effective_rules) != 1
        or not isinstance(effective_rules[0], dict)
        or set(effective_rules[0]) != set(expected_effective[0])
        or type(effective_rules[0].get("ruleset_id")) is not int
        or effective_rules != expected_effective
    ):
        _fail("FR0015_RULESET_EFFECTIVE")
    if (
        len(ruleset_history) != 1
        or not isinstance(ruleset_history[0], dict)
        or set(ruleset_history[0]) != {"actor", "updated_at", "version_id"}
        or type(ruleset_history[0].get("version_id")) is not int
        or ruleset_history[0]["version_id"] < 1
        or not isinstance(ruleset_history[0].get("actor"), dict)
        or type(ruleset_history[0]["actor"].get("id")) is not int
        or ruleset_history[0].get("actor")
        != {
            "id": identity["owner"]["id"],
            "type": identity["owner"]["type"],
        }
    ):
        _fail("FR0015_RULESET_HISTORY")
    history_item = ruleset_history[0]
    expected_version_state = {
        "id": ruleset_id,
        "name": MAIN_RULESET_NAME,
        "target": "branch",
        "source_type": "Repository",
        "source": identity["full_name"],
        "enforcement": "active",
        "conditions": conditions,
        "rules": [observed_rule],
        "updated_at": None,
        "bypass_actors": bypass_actors,
        "current_user_can_bypass": "always",
    }
    expected_version = {
        "version_id": history_item["version_id"],
        "updated_at": history_item["updated_at"],
        "actor": history_item["actor"],
        "state": expected_version_state,
    }
    if (
        set(ruleset_version) != set(expected_version)
        or type(ruleset_version.get("version_id")) is not int
        or not isinstance(ruleset_version.get("actor"), dict)
        or type(ruleset_version["actor"].get("id")) is not int
        or not isinstance(ruleset_version.get("state"), dict)
        or type(ruleset_version["state"].get("id")) is not int
        or not isinstance(ruleset_version["state"].get("bypass_actors"), list)
        or len(ruleset_version["state"]["bypass_actors"]) != 1
        or not isinstance(ruleset_version["state"]["bypass_actors"][0], dict)
        or type(ruleset_version["state"]["bypass_actors"][0].get("actor_id")) is not int
        or ruleset_version != expected_version
    ):
        _fail("FR0015_RULESET_VERSION")
    history_updated = _parse_api_timestamp(
        history_item["updated_at"],
        "ruleset.history.updated",
    )
    if history_updated < updated:
        _fail("FR0015_RULESET_CHRONOLOGY")
    return {
        "id": ruleset_id,
        "version_id": history_item["version_id"],
        "name": MAIN_RULESET_NAME,
        "owner_user_id": MAIN_RULESET_OWNER_ID,
        "enforcement": "active",
        "observed_get_rule": observed_rule,
        "omitted_update_parameter_reconstructed": False,
        "protects_against": [
            "NON_OWNER_REPOSITORY_WRITERS",
            "GITHUB_APPS",
            "DEPLOY_KEYS",
        ],
        "owner_account_compromise_protected": False,
        "mutable_external_admin_state": True,
    }


def validate_branch_protection_get(value: Any) -> dict[str, Any]:
    """Validate the exact live GET shape of the existing protected branch."""

    base = (
        f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/branches/"
        f"{REPOSITORY_DEFAULT_BRANCH}/protection"
    )
    contexts = sorted(REQUIRED_PRE_ACCEPT_CHECKS)
    expected = {
        "url": base,
        "required_status_checks": {
            "url": f"{base}/required_status_checks",
            "strict": True,
            "contexts": contexts,
            "contexts_url": f"{base}/required_status_checks/contexts",
            "checks": [
                {"context": context, "app_id": GITHUB_ACTIONS_APP_ID}
                for context in contexts
            ],
        },
        "required_signatures": {
            "url": f"{base}/required_signatures",
            "enabled": True,
        },
        "enforce_admins": {
            "url": f"{base}/enforce_admins",
            "enabled": True,
        },
        "required_linear_history": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "block_creations": {"enabled": False},
        "required_conversation_resolution": {"enabled": False},
        "lock_branch": {"enabled": False},
        "allow_fork_syncing": {"enabled": False},
    }
    if not isinstance(value, dict) or set(value) != set(expected):
        _fail("FR0015_BRANCH_PROTECTION_POLICY")
    status = value.get("required_status_checks")
    flag_names = set(expected) - {"url", "required_status_checks"}
    if (
        not isinstance(status, dict)
        or set(status) != set(expected["required_status_checks"])
        or type(status.get("strict")) is not bool
        or not isinstance(status.get("contexts"), list)
        or not all(isinstance(context, str) for context in status["contexts"])
        or not isinstance(status.get("checks"), list)
        or any(
            not isinstance(check, dict)
            or set(check) != {"app_id", "context"}
            or type(check.get("app_id")) is not int
            or not isinstance(check.get("context"), str)
            for check in status["checks"]
        )
        or any(
            not isinstance(value.get(name), dict)
            or set(value[name]) != set(expected[name])
            or type(value[name].get("enabled")) is not bool
            for name in flag_names
        )
        or value != expected
    ):
        _fail("FR0015_BRANCH_PROTECTION_POLICY")
    return copy.deepcopy(value)


def _verify_branch_protection(
    repo: Path,
    containing_commit: str,
    qualification_commit: str,
) -> dict[str, Any]:
    value, _payload = _read_json(repo, containing_commit, BRANCH_PROTECTION_PATH)
    authority = value.get("authority") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "authority",
            "branch",
            "capture",
            "effective_rules",
            "observed_commit",
            "protocol",
            "protection",
            "ref_after",
            "ref_before",
            "repository",
            "ruleset_by_id",
            "ruleset_history",
            "ruleset_list",
            "ruleset_version",
            "schema_version",
        }
        or value["schema_version"] != "1.0.0"
        or value["protocol"] != "HALDIR_FR_0015_BRANCH_PROTECTION_CAPTURE_V1"
        or value["branch"] != "main"
        or value["observed_commit"] != qualification_commit
        or not isinstance(authority, dict)
        or any(
            type(authority.get(field)) is not bool
            for field in (
                "cryptographic_proof",
                "durable_external_state_proof",
                "release_authority",
            )
        )
        or authority
        != {
            "cryptographic_proof": False,
            "durable_external_state_proof": False,
            "release_authority": False,
            "transport_observation": "GITHUB_API_OVER_TLS",
        }
    ):
        _fail("FR0015_BRANCH_PROTECTION_SCHEMA")
    repository_identity = validate_repository_identity(value["repository"])
    node_id = (
        value["ref_before"].get("node_id")
        if isinstance(value["ref_before"], dict)
        else None
    )
    expected_ref = {
        "ref": "refs/heads/main",
        "node_id": node_id,
        "url": "https://api.github.com/repos/sepahead/haldir/git/refs/heads/main",
        "object": {
            "sha": qualification_commit,
            "type": "commit",
            "url": (
                "https://api.github.com/repos/sepahead/haldir/git/commits/"
                f"{qualification_commit}"
            ),
        },
    }
    if (
        not isinstance(value["ref_before"], dict)
        or set(value["ref_before"]) != {"node_id", "object", "ref", "url"}
        or not isinstance(node_id, str)
        or not node_id
        or value["ref_before"] != expected_ref
        or value["ref_after"] != expected_ref
    ):
        _fail("FR0015_BRANCH_PROTECTION_HEAD_STABILITY")
    validate_branch_protection_get(value["protection"])
    ruleset = validate_main_writer_ruleset(
        repository_identity,
        value["ruleset_list"],
        value["ruleset_by_id"],
        value["effective_rules"],
        value["ruleset_history"],
        value["ruleset_version"],
    )
    capture = value["capture"]
    if (
        not isinstance(capture, dict)
        or set(capture)
        != {
            "captured_at_utc",
            "commit_after_command",
            "commit_before_command",
            "effective_rules_command",
            "protection_command",
            "repository_command",
            "result",
            "ruleset_get_command",
            "ruleset_history_command",
            "ruleset_list_command",
            "ruleset_version_command",
            "transport",
        }
        or capture["commit_before_command"]
        != "gh api --method GET repos/sepahead/haldir/git/ref/heads/main"
        or capture["commit_after_command"]
        != "gh api --method GET repos/sepahead/haldir/git/ref/heads/main"
        or capture["protection_command"]
        != "gh api --method GET repos/sepahead/haldir/branches/main/protection"
        or capture["repository_command"] != "gh api --method GET repos/sepahead/haldir"
        or capture["ruleset_list_command"]
        != "gh api --method GET repos/sepahead/haldir/rulesets"
        or capture["ruleset_get_command"]
        != f"gh api --method GET repos/sepahead/haldir/rulesets/{ruleset['id']}"
        or capture["ruleset_history_command"]
        != (
            "gh api --method GET repos/sepahead/haldir/rulesets/"
            f"{ruleset['id']}/history"
        )
        or capture["ruleset_version_command"]
        != (
            "gh api --method GET repos/sepahead/haldir/rulesets/"
            f"{ruleset['id']}/history/{ruleset['version_id']}"
        )
        or capture["effective_rules_command"]
        != "gh api --method GET repos/sepahead/haldir/rules/branches/main"
        or capture["transport"] != "GITHUB_API_OVER_TLS"
        or capture["result"] != "PASS"
    ):
        _fail("FR0015_BRANCH_PROTECTION_CAPTURE")
    captured = _parse_utc(capture["captured_at_utc"], "branch-protection.captured")
    if captured < _parse_git_time(
        _metadata(repo, qualification_commit)["committer_date"],
        "branch-protection.qualification",
    ) or captured > _parse_git_time(
        _metadata(repo, containing_commit)["committer_date"],
        "branch-protection.containing",
    ):
        _fail("FR0015_BRANCH_PROTECTION_CHRONOLOGY")
    result = copy.deepcopy(value)
    result["validated_ruleset_policy"] = ruleset
    return result


def _validate_local_check(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "argv",
            "result",
            "returncode",
            "stderr_bytes",
            "stderr_sha256",
            "stdout_bytes",
            "stdout_sha256",
        }
        or type(value["returncode"]) is not int
        or value["returncode"] != 0
        or value["result"] != "PASS"
        or type(value["stdout_bytes"]) is not int
        or not 0 <= value["stdout_bytes"] <= 4 * 1024 * 1024
        or type(value["stderr_bytes"]) is not int
        or not 0 <= value["stderr_bytes"] <= 4 * 1024 * 1024
        or not isinstance(value["stdout_sha256"], str)
        or HEX64.fullmatch(value["stdout_sha256"]) is None
        or not isinstance(value["stderr_sha256"], str)
        or HEX64.fullmatch(value["stderr_sha256"]) is None
        or not isinstance(value["argv"], list)
        or not all(isinstance(argument, str) for argument in value["argv"])
    ):
        _fail("FR0015_LOCAL_CHECK")
    return copy.deepcopy(value)


def _validate_local_cargo_record(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"executable", "resolver", "toolchain", "version"}
        or value["toolchain"] != "1.96.0"
        or not isinstance(value["version"], str)
        or re.fullmatch(
            r"cargo 1\.96\.0 \([0-9a-f]+ [^)]+\)",
            value["version"],
        )
        is None
        or not isinstance(value["executable"], dict)
        or set(value["executable"]) != {"bytes", "path", "sha256"}
        or not isinstance(value["executable"].get("path"), str)
        or not Path(value["executable"]["path"]).is_absolute()
        or Path(value["executable"]["path"]).name != "cargo"
        or type(value["executable"].get("bytes")) is not int
        or not 1 <= value["executable"]["bytes"] <= MAX_LOCAL_TOOL_BYTES
        or not isinstance(value["executable"].get("sha256"), str)
        or HEX64.fullmatch(value["executable"]["sha256"]) is None
        or not isinstance(value["resolver"], dict)
        or set(value["resolver"]) != {"argv", "executable"}
        or not isinstance(value["resolver"].get("executable"), dict)
        or set(value["resolver"]["executable"]) != {"bytes", "path", "sha256"}
        or not isinstance(value["resolver"]["executable"].get("path"), str)
        or not Path(value["resolver"]["executable"]["path"]).is_absolute()
        or Path(value["resolver"]["executable"]["path"]).name != "rustup"
        or type(value["resolver"]["executable"].get("bytes")) is not int
        or not 1 <= value["resolver"]["executable"]["bytes"] <= MAX_LOCAL_TOOL_BYTES
        or not isinstance(value["resolver"]["executable"].get("sha256"), str)
        or HEX64.fullmatch(value["resolver"]["executable"]["sha256"]) is None
        or value["resolver"].get("argv")
        != [
            value["resolver"]["executable"]["path"],
            "which",
            "--toolchain",
            "1.96.0",
            "cargo",
        ]
    ):
        _fail("FR0015_LOCAL_CARGO")
    return copy.deepcopy(value)


def _verify_local_evidence(
    repo: Path,
    containing_commit: str,
    repair_commit: str,
) -> dict[str, Any]:
    local, _payload = _read_json(repo, containing_commit, LOCAL_PATH)
    python_commands = (
        [
            "-I",
            "-B",
            "-W",
            "error",
            TEST_PATH,
        ],
        [
            "-I",
            "-B",
            "-W",
            "error",
            CARGO_DENY_TEST_PATH,
        ],
        [
            "-I",
            "-B",
            "-W",
            "error",
            SOURCE_PIN_VERIFIER_PATH,
        ],
        [
            "-I",
            "-B",
            "-W",
            "error",
            PIN_VERIFIER_PATH,
        ],
        [
            "-I",
            "-B",
            "-W",
            "error",
            BRIDGE_PATH,
        ],
    )
    if (
        set(local)
        != {
            "authority",
            "cargo",
            "capture_tool",
            "checks",
            "completed_at_utc",
            "protocol",
            "python",
            "result",
            "schema_version",
            "subject_commit",
            "subject_tree",
        }
        or local["schema_version"] != "1.0.0"
        or local["protocol"] != "HALDIR_FR_0015_LOCAL_VALIDATION_V1"
        or local["subject_commit"] != repair_commit
        or local["subject_tree"] != _metadata(repo, repair_commit)["tree"]
        or local["capture_tool"] != file_record(repo, repair_commit, CAPTURE_PATH)
        or local["python"] != {"implementation": "cpython", "version": "3.14.6"}
        or not isinstance(local["cargo"], dict)
        or not isinstance(local["checks"], list)
        or len(local["checks"]) != 7
        or local["result"] != "PASS"
        or local["authority"] != _authority("PENDING_QUALIFICATION")
    ):
        _fail("FR0015_LOCAL_EVIDENCE")
    _validate_local_cargo_record(local["cargo"])
    _validate_authority(
        local["authority"],
        state="PENDING_QUALIFICATION",
    )
    for index, check in enumerate(local["checks"]):
        _validate_local_check(check)
        if index < 5:
            executable = check["argv"][0] if check["argv"] else None
            if (
                not isinstance(executable, str)
                or not Path(executable).is_absolute()
                or not Path(executable).name.startswith("python3")
                or check["argv"][1:] != python_commands[index]
            ):
                _fail("FR0015_LOCAL_COMMAND")
        elif index == 5 and check["argv"] != [
            "/bin/bash",
            "-n",
            GATE_PATH,
        ]:
            _fail("FR0015_LOCAL_COMMAND")
        elif index == 6 and check["argv"] != [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "diff",
            "--check",
            f"{PARENT}..{repair_commit}",
        ]:
            _fail("FR0015_LOCAL_COMMAND")
    completed = _parse_utc(local["completed_at_utc"], "local.completed")
    if completed > _parse_git_time(
        _metadata(repo, containing_commit)["committer_date"],
        "local.containing_commit",
    ):
        _fail("FR0015_LOCAL_CHRONOLOGY")
    return local


def _verify_qualification(
    repo: Path,
    repair_commit: str,
    commit: str,
    *,
    plan: dict[str, Any],
    protocol: ModuleType,
    provisional: bool = False,
) -> dict[str, Any]:
    identity_verifier = (
        _verify_provisional_commit_identity if provisional else _verify_commit_identity
    )
    identity_verifier(repo, commit, parent=repair_commit, subject=QUALIFICATION_SUBJECT)
    if _changed_statuses(repo, repair_commit, commit) != dict(
        sorted(QUALIFICATION_STATUSES.items())
    ):
        _fail("FR0015_QUALIFICATION_DIFF")
    for path in (QUALIFICATION_PATH, *QUALIFICATION_EVIDENCE_PATHS):
        if _tree_entry(repo, commit, path)["mode"] != "100644":
            _fail("FR0015_QUALIFICATION_MODE:" + path)
    for path in (*CORE_PATHS, PLAN_PATH, *FR0014_BOUNDARY_RECORDS):
        if _tree_entry(repo, commit, path) != _tree_entry(repo, repair_commit, path):
            _fail("FR0015_QUALIFICATION_DRIFT:" + path)
    _assert_absent(
        repo,
        commit,
        sorted(
            FR0013_FORBIDDEN_COMPLETION_PATHS
            | FR0010_FORBIDDEN_COMPLETION_PATHS
            | FR0011_FORBIDDEN_COMPLETION_PATHS
            | FR0012_FORBIDDEN_COMPLETION_PATHS
        ),
    )
    hosted = {
        "repair_ci": _validate_hosted_lane(
            repo,
            commit,
            repair_commit=repair_commit,
            workflow="ci",
            subject_commit=repair_commit,
            paths=REPAIR_CI_PATHS,
            protocol=protocol,
        ),
        "repair_formal": _validate_hosted_lane(
            repo,
            commit,
            repair_commit=repair_commit,
            workflow="formal",
            subject_commit=repair_commit,
            paths=REPAIR_FORMAL_PATHS,
            protocol=protocol,
        ),
    }
    local = _verify_local_evidence(repo, commit, repair_commit)
    expected = {
        "schema_version": "1.0.0",
        "recovery_id": RECOVERY_ID,
        "stage": "QUALIFICATION",
        "state_before": "PENDING_QUALIFICATION",
        "state_after": "QUALIFIED_PENDING_ACTIVATION",
        "repair_commit": repair_commit,
        "plan_record": file_record(repo, repair_commit, PLAN_PATH),
        "evidence_catalog": _evidence_catalog(
            repo, commit, QUALIFICATION_EVIDENCE_PATHS
        ),
        "hosted_evidence": hosted,
        "local_evidence": local,
        "legacy_recovery_states": {
            "FR-0010": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0011": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0012": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0013": "SUPERSEDED_AFTER_QUALIFICATION_BEFORE_ACTIVATION",
            "FR-0014": "ACTIVE_RETIRED_AT_FR_0015_REPAIR",
        },
        "automated_paid_model_reviews": {
            "required": False,
            "normative": False,
            "authority_conferred": False,
        },
        "authority": _authority("QUALIFIED_PENDING_ACTIVATION"),
        "limitations": plan["limitations"],
    }
    if provisional:
        return expected
    value, _payload = _read_json(repo, commit, QUALIFICATION_PATH)
    unsigned = _verify_stage_signature(repo, value, namespace=QUALIFICATION_NAMESPACE)
    _validate_authority(
        unsigned.get("authority"),
        state="QUALIFIED_PENDING_ACTIVATION",
    )
    if unsigned != expected:
        _fail("FR0015_QUALIFICATION_RECORD")
    return value


def _verify_activation(
    repo: Path,
    repair_commit: str,
    qualification_commit: str,
    commit: str,
    *,
    plan: dict[str, Any],
    protocol: ModuleType,
    provisional: bool = False,
) -> dict[str, Any]:
    identity_verifier = (
        _verify_provisional_commit_identity if provisional else _verify_commit_identity
    )
    identity_verifier(
        repo,
        commit,
        parent=qualification_commit,
        subject=ACTIVATION_SUBJECT,
    )
    if _changed_statuses(repo, qualification_commit, commit) != dict(
        sorted(ACTIVATION_STATUSES.items())
    ):
        _fail("FR0015_ACTIVATION_DIFF")
    for path in (ACTIVATION_PATH, *ACTIVATION_EVIDENCE_PATHS):
        if _tree_entry(repo, commit, path)["mode"] != "100644":
            _fail("FR0015_ACTIVATION_MODE:" + path)
    for path in (
        *CORE_PATHS,
        PLAN_PATH,
        QUALIFICATION_PATH,
        *QUALIFICATION_EVIDENCE_PATHS,
        *FR0014_BOUNDARY_RECORDS,
    ):
        if _tree_entry(repo, commit, path) != _tree_entry(
            repo, qualification_commit, path
        ):
            _fail("FR0015_ACTIVATION_DRIFT:" + path)
    _assert_absent(
        repo,
        commit,
        sorted(
            FR0013_FORBIDDEN_COMPLETION_PATHS
            | FR0010_FORBIDDEN_COMPLETION_PATHS
            | FR0011_FORBIDDEN_COMPLETION_PATHS
            | FR0012_FORBIDDEN_COMPLETION_PATHS
        ),
    )
    hosted = {
        "qualification_ci": _validate_hosted_lane(
            repo,
            commit,
            repair_commit=repair_commit,
            workflow="ci",
            subject_commit=qualification_commit,
            paths=QUALIFICATION_CI_PATHS,
            protocol=protocol,
        ),
        "qualification_formal": _validate_hosted_lane(
            repo,
            commit,
            repair_commit=repair_commit,
            workflow="formal",
            subject_commit=qualification_commit,
            paths=QUALIFICATION_FORMAL_PATHS,
            protocol=protocol,
        ),
    }
    branch_protection = _verify_branch_protection(repo, commit, qualification_commit)
    expected = {
        "schema_version": "1.0.0",
        "recovery_id": RECOVERY_ID,
        "stage": "ACTIVATION",
        "state_before": "QUALIFIED_PENDING_ACTIVATION",
        "state_after": "ACTIVE",
        "repair_commit": repair_commit,
        "qualification_commit": qualification_commit,
        "plan_record": file_record(repo, repair_commit, PLAN_PATH),
        "qualification_record": file_record(
            repo, qualification_commit, QUALIFICATION_PATH
        ),
        "evidence_catalog": _evidence_catalog(repo, commit, ACTIVATION_EVIDENCE_PATHS),
        "hosted_evidence": hosted,
        "branch_protection": branch_protection,
        "activation_hosted_proof": {
            "self_attestation_available_in_activation_commit": False,
            "bound_subject": qualification_commit,
            "reason": "ACTIVATION_CANNOT_CONTAIN_HOSTED_PROOF_OF_ITSELF",
        },
        "legacy_recovery_states": {
            "FR-0010": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0011": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0012": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0013": "SUPERSEDED_AFTER_QUALIFICATION_BEFORE_ACTIVATION",
            "FR-0014": "ACTIVE_RETIRED_AT_FR_0015_REPAIR",
        },
        "authority": _authority("ACTIVE"),
        "limitations": plan["limitations"],
    }
    if provisional:
        return expected
    value, _payload = _read_json(repo, commit, ACTIVATION_PATH)
    unsigned = _verify_stage_signature(repo, value, namespace=ACTIVATION_NAMESPACE)
    _validate_authority(unsigned.get("authority"), state="ACTIVE")
    if unsigned != expected:
        _fail("FR0015_ACTIVATION_RECORD")
    return value


def _verify_successors(
    repo: Path,
    chain: list[str],
    *,
    activation_commit: str,
) -> None:
    previous = activation_commit
    for commit in chain[chain.index(activation_commit) + 1 :]:
        _verify_commit_identity(repo, commit, parent=previous, subject=None)
        statuses = _changed_statuses(repo, previous, commit)
        if (
            not statuses
            or len(statuses) > MAX_SUCCESSOR_PATHS
            or any(_successor_path_protected(path) for path in statuses)
        ):
            _fail("FR0015_SUCCESSOR_SCOPE")
        previous = commit


def _successor_path_protected(path: str) -> bool:
    folded = path.casefold()
    return path in PROTECTED_AFTER_ACTIVATION or any(
        folded.startswith(prefix.casefold())
        for prefix in PROTECTED_RECOVERY_PREFIXES_AFTER_ACTIVATION
    )


def _verify_worktree(repo: Path, commit: str, paths: Sequence[str]) -> None:
    for path in paths:
        target = repo / path
        try:
            metadata = target.lstat()
            payload = target.read_bytes()
        except OSError:
            _fail("FR0015_WORKTREE:" + path)
        entry = _tree_entry(repo, commit, path)
        expected_executable_bits = 0o111 if entry["mode"] == "100755" else 0
        observed_mode = stat.S_IMODE(metadata.st_mode)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed_mode & 0o111 != expected_executable_bits
            or observed_mode & 0o022
            or payload != _file(repo, commit, path, MAX_GIT_BYTES)
        ):
            _fail("FR0015_WORKTREE:" + path)


def verify(repo: Path) -> dict[str, Any]:
    """Verify the current first-parent epoch-16 state."""

    _verify_legacy_boundary(repo)
    head = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    ancestor = subprocess.run(
        (
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "merge-base",
            "--is-ancestor",
            PARENT,
            head,
        ),
        cwd=repo,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if ancestor.returncode != 0 or ancestor.stdout or ancestor.stderr:
        _fail("FR0015_PARENT_ANCESTRY")
    chain = (
        _git(
            repo,
            "rev-list",
            "--first-parent",
            "--reverse",
            f"{PARENT}..{head}",
        )
        .decode("ascii")
        .splitlines()
    )
    if not chain:
        _fail("FR0015_REPAIR_MISSING")
    repair_commit = chain[0]
    plan = _verify_repair(repo, repair_commit)
    protocol = _load_protocol_module(repo, repair_commit)
    state = "PENDING_QUALIFICATION"
    qualification_commit: str | None = None
    activation_commit: str | None = None
    if len(chain) >= 2:
        qualification_commit = chain[1]
        _verify_qualification(
            repo,
            repair_commit,
            qualification_commit,
            plan=plan,
            protocol=protocol,
        )
        state = "QUALIFIED_PENDING_ACTIVATION"
    if len(chain) >= 3:
        activation_commit = chain[2]
        _verify_activation(
            repo,
            repair_commit,
            qualification_commit,
            activation_commit,
            plan=plan,
            protocol=protocol,
        )
        state = "ACTIVE"
        _verify_successors(repo, chain, activation_commit=activation_commit)
    worktree_paths: list[str] = [
        *CORE_PATHS,
        PLAN_PATH,
        *FR0014_BOUNDARY_RECORDS,
        *HISTORICAL_RECOVERY_TOOL_PATHS,
        ALLOWED_SIGNERS_PATH,
        "tools/release/verify-current-audit.py",
        "tools/release/test_verify_current_audit_fr_0009.py",
    ]
    if qualification_commit is not None:
        worktree_paths.extend((QUALIFICATION_PATH, *QUALIFICATION_EVIDENCE_PATHS))
    if activation_commit is not None:
        worktree_paths.extend((ACTIVATION_PATH, *ACTIVATION_EVIDENCE_PATHS))
    _verify_worktree(repo, head, sorted(set(worktree_paths)))
    _assert_absent(
        repo,
        head,
        sorted(
            FR0013_FORBIDDEN_COMPLETION_PATHS
            | FR0010_FORBIDDEN_COMPLETION_PATHS
            | FR0011_FORBIDDEN_COMPLETION_PATHS
            | FR0012_FORBIDDEN_COMPLETION_PATHS
        ),
    )
    return {
        "head": head,
        "repair_commit": repair_commit,
        "qualification_commit": qualification_commit,
        "activation_commit": activation_commit,
        "state": state,
        "authority": _authority(state),
    }


def expected_record_for_provisional(
    repo: Path,
    *,
    stage: str,
    provisional_commit: str,
) -> dict[str, Any]:
    """Derive one unsigned R/Q/A record from an exact provisional tree."""

    _verify_legacy_boundary(repo)
    if stage == "plan":
        _verify_provisional_commit_identity(
            repo,
            provisional_commit,
            parent=PARENT,
            subject=REPAIR_SUBJECT,
        )
        _verify_repair_tree(repo, provisional_commit)
        return expected_plan(repo, provisional_commit)
    metadata = _metadata(repo, provisional_commit)
    parent = metadata["parents"]
    if HEX40.fullmatch(parent) is None:
        _fail("FR0015_PROVISIONAL_PARENT")
    if stage == "qualification":
        repair_commit = parent
        plan = _verify_repair(repo, repair_commit)
        protocol = _load_protocol_module(repo, repair_commit)
        return _verify_qualification(
            repo,
            repair_commit,
            provisional_commit,
            plan=plan,
            protocol=protocol,
            provisional=True,
        )
    if stage == "activation":
        qualification_commit = parent
        repair_commit = _metadata(repo, qualification_commit)["parents"]
        if HEX40.fullmatch(repair_commit) is None:
            _fail("FR0015_PROVISIONAL_PARENT")
        plan = _verify_repair(repo, repair_commit)
        protocol = _load_protocol_module(repo, repair_commit)
        _verify_qualification(
            repo,
            repair_commit,
            qualification_commit,
            plan=plan,
            protocol=protocol,
        )
        return _verify_activation(
            repo,
            repair_commit,
            qualification_commit,
            provisional_commit,
            plan=plan,
            protocol=protocol,
            provisional=True,
        )
    _fail("FR0015_PROVISIONAL_STAGE")


def _repo() -> Path:
    completed = subprocess.run(
        ("/usr/bin/git", "rev-parse", "--show-toplevel"),
        cwd=Path.cwd(),
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        _fail("FR0015_REPOSITORY")
    try:
        return Path(completed.stdout.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _fail("FR0015_REPOSITORY")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    generators = parser.add_mutually_exclusive_group()
    generators.add_argument(
        "--print-expected-plan",
        metavar="REPAIR_COMMIT",
        help="print the unsigned canonical plan for a provisional repair commit",
    )
    generators.add_argument(
        "--print-expected-qualification",
        metavar="QUALIFICATION_COMMIT",
        help="print the unsigned qualification record for a provisional commit",
    )
    generators.add_argument(
        "--print-expected-activation",
        metavar="ACTIVATION_COMMIT",
        help="print the unsigned activation record for a provisional commit",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repo = _repo()
        requested = [
            ("plan", arguments.print_expected_plan),
            ("qualification", arguments.print_expected_qualification),
            ("activation", arguments.print_expected_activation),
        ]
        selected = [(stage, commit) for stage, commit in requested if commit]
        if selected:
            stage, provisional_commit = selected[0]
            print(
                canonical_json_bytes(
                    expected_record_for_provisional(
                        repo,
                        stage=stage,
                        provisional_commit=provisional_commit,
                    )
                ).decode("utf-8"),
                end="",
            )
            return 0
        result = verify(repo)
    except (
        BridgeError,
        OSError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"verify-framework-recovery-fr-0015: {error}", file=sys.stderr)
        return 1
    print(
        "verify-framework-recovery-fr-0015: OK "
        f"({result['state']}; epoch 16; release NO_GO)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
