#!/usr/bin/env python3
"""Verify the append-only FR-0017 epoch-18 trust-root transition.

The signed FR-0016 repair is an immutable, unqualified historical boundary.
Its verifier and every earlier recovery verifier are inert here.  This bridge
verifies that repair, its detached plan, the preceding signed FR-0015 active
boundary, and the intervening signed linear milestones directly.  It then
validates only the deterministic FR-0017 R/Q/A sequence and ordinary signed
linear milestones after activation.

Epoch-18 hosted-result artifacts convey provenance only and grant no release
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


PARENT = "7e5015092d5a4de3556b252e594c59c72636e7b9"
PARENT_TREE = "e5aac716964bc14a5c907e825dff229c9797ae4d"
PARENT_PARENT = "ec207cbdba36f15a410206fd01e76a54ffd29ac0"
PARENT_SUBJECT = "release: establish epoch-17 audit trust root"
M16_COMMIT = PARENT_PARENT
M16_TREE = "1b7e4b32576fab770aeaee0770335af50544149c"
M16_PARENT = "d441316189acad8fd2063d523399021684a2d0ca"
M16_SUBJECT = "plant: make runtime transitions fail closed"
FR0015_REPAIR = "c06465d5ac9f6413067ce9ff79e135f3c6ba898e"
FR0015_REPAIR_PARENT = "e98924aa5dfd36169febf9a47aa7a15b44548e31"
FR0015_REPAIR_TREE = "6b88759e6b0787cb801c4cb3bcf2abe23bf9404b"
FR0015_REPAIR_SUBJECT = "release: establish epoch-16 audit trust root"
FR0015_QUALIFICATION = "60f43a3afdbad84050fc424a43ffd6b9602ac200"
FR0015_QUALIFICATION_TREE = "0928b0d049f4ae2e62f55934a29a880b4b213b39"
FR0015_QUALIFICATION_SUBJECT = "release: qualify epoch-16 audit trust root"
FR0015_ACTIVATION = "18b4a605844b39f43193d35f487a3272f7800e87"
FR0015_ACTIVATION_TREE = "a283dae6d938433d1bf6e16e94aff42feab858f6"
FR0015_ACTIVATION_SUBJECT = "release: activate epoch-16 audit trust root"
FR0015_SUCCESSORS = (
    (
        "fd349e51eff9f3900f0fcf225dd0a0a70e1fbe41",
        FR0015_ACTIVATION,
        "2ef181040211ba3cc0d63e20073974908beadfb1",
        "docs: align supply-chain status with epoch 16",
    ),
    (
        "2790882d0f4daf52b38856317f920a5fccac1db0",
        "fd349e51eff9f3900f0fcf225dd0a0a70e1fbe41",
        "27a5afe95f628291a8781c07b0148f45340bf693",
        "policy: make action-history accounting exact",
    ),
    (
        "7996d7d0a2928b0ef2ff4ab34f510ea287917ac7",
        "2790882d0f4daf52b38856317f920a5fccac1db0",
        "c200815c0e771b5676191ae01c9743b6a91bd515",
        "docs: align audit and security guidance",
    ),
    (
        "6d89da8fbb382b08533f48e495bfa4bfc6010cbb",
        "7996d7d0a2928b0ef2ff4ab34f510ea287917ac7",
        "89b572085549f317bbff649c4c206dce4b39e8b4",
        "build: remove duplicate local audit pass",
    ),
    (
        "f41cbb6373f82f123ce65903bb539a66b0976015",
        "6d89da8fbb382b08533f48e495bfa4bfc6010cbb",
        "d53a1503a241723268a7f558e7b0a6d6f32c69ea",
        "formal: add verified local model runner",
    ),
    (
        "42e14e274437340a81c6b379a505de6aaeb72e40",
        "f41cbb6373f82f123ce65903bb539a66b0976015",
        "2985fa634abc4ef189598a408758c81375951247",
        "state: prevent output epoch reactivation",
    ),
    (
        "ea0dc9690fb9e4ceeced24a754b3bf081aa0de5b",
        "42e14e274437340a81c6b379a505de6aaeb72e40",
        "02355cd872c4e54fdb3927e1cc9c16dcc765fd1c",
        "contracts: validate decision receipt semantics",
    ),
    (
        "065c0e9425fca485f77cb60b9099fc2405977273",
        "ea0dc9690fb9e4ceeced24a754b3bf081aa0de5b",
        "1759aabfcb821005410c5b9d3ef6d35113006f88",
        "contracts: enforce exact v1.0 schema versions",
    ),
    (
        "6649567e9669743fe515b71282efb142143f8405",
        "065c0e9425fca485f77cb60b9099fc2405977273",
        "f3979932352560daefaf429b580d580137593756",
        "gate: make CLI introspection truthful",
    ),
    (
        "d441316189acad8fd2063d523399021684a2d0ca",
        "6649567e9669743fe515b71282efb142143f8405",
        "b7a00fa58b8353f0d03780b5946bea8fa43bbcb0",
        "errors: standardize durable evidence contracts",
    ),
    (
        M16_COMMIT,
        M16_PARENT,
        M16_TREE,
        M16_SUBJECT,
    ),
)
RECOVERY_ID = "FR-0017"
REPAIR_SUBJECT = "release: supersede incomplete epoch-17 recovery"
QUALIFICATION_SUBJECT = "release: qualify epoch-18 audit trust root"
ACTIVATION_SUBJECT = "release: activate epoch-18 audit trust root"
PLAN_NAMESPACE = "haldir-framework-recovery-fr-0017-plan-v1"
FR0015_PLAN_NAMESPACE = "haldir-framework-recovery-fr-0015-plan-v1"
FR0015_QUALIFICATION_NAMESPACE = "haldir-framework-recovery-fr-0015-qualification-v1"
FR0015_ACTIVATION_NAMESPACE = "haldir-framework-recovery-fr-0015-activation-v1"
FR0016_PLAN_NAMESPACE = "haldir-framework-recovery-fr-0016-plan-v1"
QUALIFICATION_NAMESPACE = "haldir-framework-recovery-fr-0017-qualification-v1"
ACTIVATION_NAMESPACE = "haldir-framework-recovery-fr-0017-activation-v1"
SIGNER_PRINCIPAL = "sepmhn@gmail.com"
SIGNER_FINGERPRINT = "SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU"
AUTHOR_NAME = "Sepehr Mahmoudian"
AUTHOR_EMAIL = "sepmhn@gmail.com"
ALLOWED_SIGNERS_PATH = "release/0.9.0/allowed-signers"
PLAN_PATH = "release/0.9.0/current-head/closures/framework-recovery/FR-0017-plan.json"
QUALIFICATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0017-qualification.json"
)
ACTIVATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0017-activation.json"
)
FR0015_PLAN_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0015-plan.json"
)
FR0015_QUALIFICATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0015-qualification.json"
)
FR0015_ACTIVATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0015-activation.json"
)
FR0016_PLAN_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0016-plan.json"
)
MODULE_PATH = "tools/release/framework_recovery_fr_0017.py"
CAPTURE_PATH = "tools/release/framework_recovery_fr_0017_capture.py"
RESULT_PATH = "tools/release/framework_recovery_fr_0017_result.py"
BRIDGE_PATH = "tools/release/verify-framework-recovery-fr-0017.py"
TEST_PATH = "tools/release/test_verify_framework_recovery_fr_0017.py"
TRUSTED_ROOT_PATH = "tools/release/sigstore-public-good-trusted-root.jsonl"
GATE_PATH = "tools/release/current-audit-gate.sh"
PIN_VERIFIER_PATH = "tools/verify-ci-pins.py"
SOURCE_PIN_VERIFIER_PATH = "tools/verify-pins.py"
SUPPLY_PIN_PATH = "tools/pins.toml"
CARGO_DENY_INSTALLER_PATH = "tools/pinned_cargo_deny.py"
CARGO_DENY_TEST_PATH = "tools/test_pinned_cargo_deny.py"
FORMAL_RUNNER_PATH = "tools/run_formal.py"
FORMAL_RUNNER_TEST_PATH = "tools/test_run_formal.py"
FORMAL_README_PATH = "formal/README.md"
JUSTFILE_PATH = "justfile"
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
    FORMAL_RUNNER_PATH,
    FORMAL_RUNNER_TEST_PATH,
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
    FORMAL_RUNNER_PATH: "100755",
    FORMAL_RUNNER_TEST_PATH: "100644",
    FORMAL_README_PATH: "100644",
    JUSTFILE_PATH: "100644",
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
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-r-ci-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-r-ci-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-r-ci-attestation.json",
)
REPAIR_FORMAL_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-r-formal-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-r-formal-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-r-formal-attestation.json",
)
LOCAL_PATH = f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-r-local.json"
PULL_REQUEST_PATH = f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-r-pull-request.json"
QUALIFICATION_EVIDENCE_PATHS = (
    *REPAIR_CI_PATHS,
    *REPAIR_FORMAL_PATHS,
    LOCAL_PATH,
    PULL_REQUEST_PATH,
)
QUALIFICATION_STATUSES = {
    QUALIFICATION_PATH: "A",
    **{path: "A" for path in QUALIFICATION_EVIDENCE_PATHS},
}
QUALIFICATION_CI_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-q-ci-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-q-ci-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-q-ci-attestation.json",
)
QUALIFICATION_FORMAL_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-q-formal-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-q-formal-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-q-formal-attestation.json",
)
BRANCH_PROTECTION_PATH = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-branch-protection.json"
)
HOSTED_SETTINGS_PATH = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0017-hosted-settings.json"
)
ACTIVATION_EVIDENCE_PATHS = (
    *QUALIFICATION_CI_PATHS,
    *QUALIFICATION_FORMAL_PATHS,
    BRANCH_PROTECTION_PATH,
    HOSTED_SETTINGS_PATH,
)
ACTIVATION_STATUSES = {
    ACTIVATION_PATH: "A",
    **{path: "A" for path in ACTIVATION_EVIDENCE_PATHS},
}

FR0015_BOUNDARY_RECORDS = {
    ALLOWED_SIGNERS_PATH: {
        "git_mode": "100644",
        "git_object_id": "7e563049b65dc6761e76b7d0c96c1cc10bd5c0dc",
        "sha256": "88eddddf1b3a6d0176acf2ec88b1d3c120453e2658651c49b82d41057caa78ed",
        "bytes": 98,
    },
    FR0015_PLAN_PATH: {
        "git_mode": "100644",
        "git_object_id": "74b0ba739488ee1842dbff5feb280e8b2247f91e",
        "sha256": "e9f406d9e15b38fbe03305a78708f33231959f6c7f3c59b2e3b60bbbc16a7af7",
        "bytes": 48_560,
    },
    FR0015_QUALIFICATION_PATH: {
        "git_mode": "100644",
        "git_object_id": "7ba1eefcc2c11e1eecb6172cf745ff370bf3e91c",
        "sha256": "d696753aeb936fb1cab9efc2bb4f35346220adcaa334edbd372786207a38a15a",
        "bytes": 20_524,
    },
    FR0015_ACTIVATION_PATH: {
        "git_mode": "100644",
        "git_object_id": "aab4f15a7e5e41f3dc32f10603572c3c5e5744ba",
        "sha256": "f60ceef439488a18de8969c1668fa147e617aa4224fe0030da344c9fc75b40c2",
        "bytes": 23_584,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-ci-attestation.json": {
        "git_mode": "100644",
        "git_object_id": "8b4d0b27eaf443e87bd3c7faac62600d27f13466",
        "sha256": "32c7ace76d1de1cc0110009627a7d818402af6de386597a0f46a1eb897799d4d",
        "bytes": 10_296,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-ci-capture.json": {
        "git_mode": "100644",
        "git_object_id": "32f5b9dcb58b39978be3e33df8d9080de2fb559d",
        "sha256": "f99ba232fcf668b7524fdb8413891791a85def6cd5098c37b4eeb4941307f3f7",
        "bytes": 65_576,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-ci-result.json": {
        "git_mode": "100644",
        "git_object_id": "2b9bc29c02118443262da46d295a79a5a8bf6c69",
        "sha256": "cdefebc8853b997d7a7413c03f72893a6614768f504df227023f4da3719df54b",
        "bytes": 5_340,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-formal-attestation.json": {
        "git_mode": "100644",
        "git_object_id": "f7594da50802f3d9a606949510e24a88f982e7e1",
        "sha256": "c8cacc48fd8e0b71c12d43388eb7774d2fe6b232296281822c611bbb9a9608ac",
        "bytes": 10_137,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-formal-capture.json": {
        "git_mode": "100644",
        "git_object_id": "d357e5a2660c4d77dd29601cae24ad63ffeab4cc",
        "sha256": "f5fb14935b3eebd98692e53a006a338d2cdc667a6a0c93eb635212f684cf9138",
        "bytes": 32_350,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-formal-result.json": {
        "git_mode": "100644",
        "git_object_id": "af94766cb37e647c76c9baeae8db2c71ef333149",
        "sha256": "166a5b133840da251834dfa8a42611ef966d55ae75b041e4c571ff429d3d6bda",
        "bytes": 3_069,
    },
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0015-r-local.json": {
        "git_mode": "100644",
        "git_object_id": "a5cd8b52eecaf6773b5caaac5dd1dd1a9e2532fd",
        "sha256": "3394616b6ad21cad2292e61b65c5f3eaa0ad658489828c93c551680168eb023e",
        "bytes": 5_324,
    },
    TRUSTED_ROOT_PATH: {
        "git_mode": "100644",
        "git_object_id": "7fa44c8fde4afb1dc889c4284245b1dbcf30525d",
        "sha256": "3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1",
        "bytes": 5_748,
    },
    "tools/release/framework_recovery_fr_0015.py": {
        "git_mode": "100644",
        "git_object_id": "144d7745bfa5001da68783a1bc9048229802152b",
        "sha256": "6f1936aba9c8d88f90474cb47c1d9ac3e39eae21566e4dcb3eac6796af51278e",
        "bytes": 33_932,
    },
    "tools/release/framework_recovery_fr_0015_capture.py": {
        "git_mode": "100755",
        "git_object_id": "446f3d2b6158f3f6c6bcef86248af36b50ac3fc4",
        "sha256": "c097f7515a6d7726ebc2addcca3855bf11e3de3e9101ddd53a5f605c0144daa2",
        "bytes": 38_697,
    },
    "tools/release/framework_recovery_fr_0015_result.py": {
        "git_mode": "100755",
        "git_object_id": "cb4fdc83e0163519fb688c7ee9163cbffd5eb342",
        "sha256": "42bcc3488049fbd0bf43db94eb8f5a1c1504bb58df29507c91682137624f90fe",
        "bytes": 10_455,
    },
    "tools/release/test_verify_framework_recovery_fr_0015.py": {
        "git_mode": "100644",
        "git_object_id": "888978acdae4b06da4641ff0c19ec536f9421707",
        "sha256": "cde629277f9eb2f7b18efff218477c8722cefd22dbee4dffe4d04552bec0b707",
        "bytes": 122_349,
    },
    "tools/release/verify-framework-recovery-fr-0015.py": {
        "git_mode": "100755",
        "git_object_id": "244338c6be7f14017032bbd3db25bce55fbc58a5",
        "sha256": "04c1cb3569315a1c38d393fa83804b98a04236f950e6345b1769caa8c1e774fb",
        "bytes": 128_807,
    },
}

FR0016_BOUNDARY_RECORDS = {
    path: {
        "git_mode": mode,
        "git_object_id": object_id,
        "sha256": digest,
        "bytes": byte_count,
    }
    for path, mode, object_id, digest, byte_count in (
        (
            ".github/workflows/ci.yml",
            "100644",
            "0298e5dbfcee0996cad683a04dafde734839605f",
            "6d73fc19604d950e7e02f1c1434332b5cd9415c5064fdb3e1f44208c881b7b98",
            19_637,
        ),
        (
            ".github/workflows/formal.yml",
            "100644",
            "b93f855eba8b6646550f7928d8bb8a99f4d0f8aa",
            "6418e4abb9899d78feb4b1f8bb539af5d24532d2e5ffc6fb7707950b8d084932",
            16_546,
        ),
        (
            "formal/README.md",
            "100644",
            "2eff746106b0df76400335fea70769ff30b1d736",
            "c6a2470c22b4da7620e30494a44638fd998b122efb4c02ed9a8ff374eaf338ce",
            4_382,
        ),
        (
            "justfile",
            "100644",
            "3392ea9e03ad08fa589f4fc46802d510c9f9942b",
            "c1202aa8e324915ee5a566f08fbe1781eb6c59a6f18419b46db57f8e650b2f78",
            3_068,
        ),
        (
            ALLOWED_SIGNERS_PATH,
            "100644",
            "7e563049b65dc6761e76b7d0c96c1cc10bd5c0dc",
            "88eddddf1b3a6d0176acf2ec88b1d3c120453e2658651c49b82d41057caa78ed",
            98,
        ),
        (
            FR0016_PLAN_PATH,
            "100644",
            "03675a07196513416e27a07a5850238c40c78194",
            "3c2f801e0865392f38e675f31d5b89f041194f74958391603d8e467f4ddabe6a",
            65_691,
        ),
        (
            "tools/pinned_cargo_deny.py",
            "100644",
            "d444cc7560a81122e102ab851ff9f83eb074293b",
            "df6f79404627904d7b97a727eb02c36696306506c6772d7cdec865da0e49b8fe",
            51_291,
        ),
        (
            "tools/pins.toml",
            "100644",
            "73c7e35ea071fc77fe85d299f6af70ad7f6baa9b",
            "b3cff5846bb5dd42ba5a233a41e3c90330d2fcb689a8ae7681de3e6458e05250",
            5_150,
        ),
        (
            "tools/release/current-audit-gate.sh",
            "100755",
            "39a59192d51a5a4b195da4e30705e9905128607d",
            "c99794bd5d07e1bcbaf25adeac37a671fbbc567caf9c3d58bb0df590bce9b0cd",
            3_403,
        ),
        (
            "tools/release/framework_recovery_fr_0016.py",
            "100644",
            "0fe4293999345b025509578f1bbb17dc4de7d6d1",
            "671055f432684807f687dca1fa1e9b9431a9bb68e23464a04534586087b47067",
            41_207,
        ),
        (
            "tools/release/framework_recovery_fr_0016_capture.py",
            "100755",
            "b9e6aa9361327d508531c2c55ae8b29ee369fa9f",
            "a4d5a6fe263f3297eb21048378813f729bb4a1a9c284c5c8b31669ed91f37e01",
            76_159,
        ),
        (
            "tools/release/framework_recovery_fr_0016_result.py",
            "100755",
            "c7f1b40625b39d1ee55f2f07b3b103421edcb4df",
            "d2e8d3fc4b3435e2dbbaa2c22927d484424af4a11f462df1d0658d0c716bec8e",
            10_770,
        ),
        (
            "tools/release/test_verify_framework_recovery_fr_0016.py",
            "100644",
            "76631287275cfa11ecdab247c8463abe731ab6d6",
            "cfbc19edbfb36c60c326768729bf62ccff1e049b1b53943c5b1816429edee4b4",
            168_458,
        ),
        (
            "tools/release/verify-framework-recovery-fr-0016.py",
            "100755",
            "8ab7d99712544042615ccc3145a935064a97f282",
            "ebac98b7ce5bddb8133d0e1976fea3b8cfc4b63ec780beb306ed4f9956bf7e23",
            168_543,
        ),
        (
            "tools/run_formal.py",
            "100755",
            "e53f7b706a995d79062549c27d690eb819966212",
            "546d0fc4041840ee63c7aefffce21e0b51403b448a02b4133a77fc3ed32d6d94",
            56_688,
        ),
        (
            "tools/test_pinned_cargo_deny.py",
            "100644",
            "5364cac3b4c4f640d7e837475e995bac85ff8972",
            "5677354cbe84e101a5a1cd0c693cecc82b4613b973b31098760d586580065889",
            79_669,
        ),
        (
            "tools/test_run_formal.py",
            "100644",
            "abe966aa6272bdd4a4cbd3a09a573752ee295b9d",
            "70209d68beb3953e2e015a6293c2c6d8baded188d928b1fef1cc88fd9b8d404f",
            89_541,
        ),
        (
            "tools/verify-ci-pins.py",
            "100755",
            "6e1476651c6b18564ac964cb31b80a1ce9222ba9",
            "841e3cd0dbc0595c68394b804c598d364065c4c9d3555589849e4905f328a58e",
            50_348,
        ),
        (
            "tools/verify-pins.py",
            "100644",
            "5a456d2c1fd56629e0bf2db5f318ca620acab58d",
            "c1621eeedb10a4585c826e088519878b41245dda372b70b77da7ce0e5add51b8",
            15_356,
        ),
    )
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
        "tools/release/framework_recovery_fr_0015.py",
        "tools/release/framework_recovery_fr_0015_capture.py",
        "tools/release/framework_recovery_fr_0015_result.py",
        "tools/release/test_verify_framework_recovery_fr_0015.py",
        "tools/release/verify-framework-recovery-fr-0015.py",
        "tools/release/framework_recovery_fr_0016.py",
        "tools/release/framework_recovery_fr_0016_capture.py",
        "tools/release/framework_recovery_fr_0016_result.py",
        "tools/release/test_verify_framework_recovery_fr_0016.py",
        "tools/release/verify-framework-recovery-fr-0016.py",
    }
)

FR0016_FORBIDDEN_COMPLETION_PATHS = frozenset(
    {
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0016-qualification.json"
        ),
        (
            "release/0.9.0/current-head/closures/framework-recovery/"
            "FR-0016-activation.json"
        ),
        *{
            f"{EVIDENCE_ROOT}/framework-recovery-fr-0016-{stage}-{workflow}-{kind}.json"
            for stage in ("r", "q")
            for workflow in ("ci", "formal")
            for kind in ("capture", "result", "attestation")
        },
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0016-r-local.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0016-r-pull-request.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0016-branch-protection.json",
        f"{EVIDENCE_ROOT}/framework-recovery-fr-0016-hosted-settings.json",
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
FORMAL_PIN_CONTRACT = {
    "schema_version": 3,
    "formal": {
        "tla_tools_version": "1.7.4",
        "tla_tools_bytes": 2_274_532,
        "tla_tools_sha256": (
            "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
        ),
        "java_distribution": "temurin",
        "java_release_tag": "jdk-21.0.11+10",
        "java_archive_package": "jre",
        "java_archive_architecture": "x64",
        "java_archive_name": ("OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz"),
        "java_archive_root": "jdk-21.0.11+10-jre",
        "java_archive_url": (
            "https://github.com/adoptium/temurin21-binaries/releases/download/"
            "jdk-21.0.11%2B10/"
            "OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz"
        ),
        "java_archive_bytes": 52_099_793,
        "java_archive_sha256": (
            "e5038aae3ca9ff670bc696496b0728dbd23d280026bad30291cb919221ecfdcb"
        ),
        "java_runtime_vendor": "Eclipse Adoptium",
        "java_runtime_version": "21.0.11+10-LTS",
        "java_specification_version": "21",
        "java_runtime_architecture": "amd64",
    },
}
FORMAL_WORKFLOW_COMMAND = (
    "/usr/bin/env -u JAVA_TOOL_OPTIONS -u _JAVA_OPTIONS "
    "-u JDK_JAVA_OPTIONS LC_ALL=C "
    '"${JAVA_HOME}/bin/java" -XX:+UseParallelGC '
    '-cp "$TLA_TOOLS_PATH" tlc2.TLC -workers auto '
    "-config formal/HaldirAuthority.cfg formal/HaldirAuthority.tla"
)
LOCAL_FORMAL_RUNTIME_ARCHITECTURES = ("aarch64", "amd64", "x86_64")
PULL_REQUEST_EVENT_CONTRACT = {
    "checkout_sha": "PULL_REQUEST_SYNTHETIC_MERGE_COMMIT",
    "run_head_sha": "PULL_REQUEST_HEAD_COMMIT",
    "workflow_checkout_ref_override": False,
}
HOSTED_SETTINGS_EXPECTED_POLICY = {
    "actions_permissions": {
        "allowed_actions": "selected",
        "enabled": True,
        "selected_actions_url": (
            "https://api.github.com/repositories/1292802592/actions/"
            "permissions/selected-actions"
        ),
        "sha_pinning_required": True,
    },
    "dependabot_security_updates": {"enabled": True, "paused": False},
    "fork_pull_request_contributor_approval": {
        "approval_policy": "first_time_contributors"
    },
    "private_vulnerability_reporting": {"enabled": True},
    "repository_security_and_analysis": {
        "dependabot_security_updates": {"status": "enabled"},
        "secret_scanning": {"status": "enabled"},
        "secret_scanning_non_provider_patterns": {"status": "disabled"},
        "secret_scanning_push_protection": {"status": "enabled"},
        "secret_scanning_validity_checks": {"status": "disabled"},
    },
    "selected_actions": {
        "github_owned_allowed": True,
        "patterns_allowed": [],
        "verified_allowed": False,
    },
    "vulnerability_alerts": {"enabled": True, "http_status": 204},
    "workflow_permissions": {
        "can_approve_pull_request_reviews": False,
        "default_workflow_permissions": "read",
    },
}
HOSTED_SETTINGS_HISTORY_SCOPE = {
    "activation_commit_self_observed": False,
    "durable_historical_transition_proof": False,
    "observation_scope": "QUALIFICATION_COMMIT_ONLY",
    "settings_transition_time_claimed": False,
}
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
        *FR0016_BOUNDARY_RECORDS,
        *FR0015_BOUNDARY_RECORDS,
        *HISTORICAL_RECOVERY_TOOL_PATHS,
        *FR0016_FORBIDDEN_COMPLETION_PATHS,
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
    """One fail-closed epoch-18 bridge error."""


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
        _fail("FR0017_GIT:" + (arguments[0] if arguments else "missing"))
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
        _fail("FR0017_COMMIT_METADATA")
    try:
        values = [field.decode("utf-8") for field in fields]
    except UnicodeDecodeError:
        _fail("FR0017_COMMIT_METADATA")
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
        _fail("FR0017_COMMIT_METADATA")
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
        _fail("FR0017_COMMIT_IDENTITY")
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
        _fail("FR0017_COMMIT_SIGNATURE")
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
        _fail("FR0017_PROVISIONAL_COMMIT_IDENTITY")
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
        _fail("FR0017_DIFF_GRAMMAR")
    result: dict[str, str] = {}
    for index in range(0, len(parts), 2):
        try:
            status = parts[index].decode("ascii")
            path = parts[index + 1].decode("utf-8")
        except UnicodeDecodeError:
            _fail("FR0017_DIFF_GRAMMAR")
        if (
            status not in {"A", "M", "D"}
            or path in result
            or path.startswith("/")
            or "//" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            _fail("FR0017_DIFF_GRAMMAR")
        result[path] = status
    return dict(sorted(result.items()))


def _tree_entry(repo: Path, commit: str, path: str) -> dict[str, str]:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path, limit=64 * 1024)
    if raw.count(b"\0") != 1 or not raw.endswith(b"\0"):
        _fail("FR0017_TREE_ENTRY:" + path)
    try:
        header, observed = raw[:-1].split(b"\t", 1)
        mode, object_type, oid = header.decode("ascii").split(" ")
        decoded = observed.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        _fail("FR0017_TREE_ENTRY:" + path)
    if (
        decoded != path
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or HEX40.fullmatch(oid) is None
    ):
        _fail("FR0017_TREE_ENTRY:" + path)
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
        _fail("FR0017_JSON:" + path)
    if not isinstance(value, dict) or payload != canonical_json_bytes(value):
        _fail("FR0017_JSON_CANONICAL:" + path)
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
        or not record["signature"]
        or len(record["signature"]) > 16 * 1024
    ):
        _fail("FR0017_DETACHED_SIGNATURE")
    try:
        signature_payload = record["signature"].encode("ascii")
    except UnicodeEncodeError:
        _fail("FR0017_DETACHED_SIGNATURE")
    with tempfile.TemporaryDirectory(prefix="haldir-fr0017-signature-") as name:
        signature_path = Path(name) / "signature"
        signature_path.write_bytes(signature_payload)
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
        _fail("FR0017_DETACHED_SIGNATURE")


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
        "framework_epoch": 18,
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
    framework_epoch: int = 18,
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
        _fail("FR0017_AUTHORITY_SCHEMA")


def expected_plan(repo: Path, repair_commit: str) -> dict[str, Any]:
    """Return the exact unsigned FR-0017 repair plan."""

    formal_pins = FORMAL_PIN_CONTRACT["formal"]
    limitations = [
        (
            "FR-0016 main formal run 30563526533 succeeded, but FR-0016 "
            "never reached qualification. That observation is nonnormative, "
            "is not committed in an FR-0016 completion path, and is not "
            "reused as FR-0017 evidence."
        ),
        (
            "GitHub OIDC proves the isolated attestation workflow identity; "
            "the producer result remains a statement from repository code."
        ),
        (
            "The epoch-18 artifact syntax is an evidence transport only and "
            "confers no release authority."
        ),
        (
            "The temporary pull-request record binds the repair head, GitHub's "
            "two-parent synthetic merge object, the signed workflow's default "
            "checkout configuration, and successful required jobs. GitHub's "
            "run API reports the pull-request head commit rather than the "
            "synthetic merge commit, so the checkout-SHA conclusion relies on "
            "the signed workflow plus GitHub pull_request event semantics; no "
            "independent runtime attestation of the checked-out SHA is claimed."
        ),
        (
            "cargo-deny and RustSec acquisition still require network "
            "availability, but exact size and SHA-256 identities are checked "
            "before either input is installed or executed."
        ),
        (
            "The hosted Temurin and TLA+ acquisitions require network "
            "availability. Exact byte lengths and SHA-256 identities prove "
            "equality to the reviewed archives, not an independently "
            "reproduced upstream Java build."
        ),
        (
            "The pinned Temurin archive is the hosted Linux x64 input only. "
            "Local formal evidence separately records an admitted runtime "
            "architecture and does not claim byte identity with that hosted "
            "archive."
        ),
        (
            "The hosted extraction validates the reviewed archive's legal "
            "symlink manifest and excludes the complete legal subtree before "
            "runtime use. It proves evaluator execution, not a complete Java "
            "redistribution artifact."
        ),
        (
            "The dependency-policy execution is frozen and network-isolated; "
            "the pinned RustSec snapshot is rejected after its finite 90-day "
            "staleness window and requires an intentional signed refresh."
        ),
        (
            "Branch-protection and hosted-settings API evidence are "
            "TLS-observed snapshots of mutable external state, not durable "
            "cryptographic proof."
        ),
        (
            "Epoch 18 performs no branch-control or hosted-settings mutation. "
            "Activation captures the existing state at the qualification "
            "commit through bounded GET requests and proves neither when the "
            "settings transitioned nor that they remained unchanged before or "
            "after the observation."
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
            "state": "HISTORICAL_SIGNED_FR_0016_REPAIR_BOUNDARY",
            "commit": PARENT,
            "tree": PARENT_TREE,
            "parent": PARENT_PARENT,
            "subject": PARENT_SUBJECT,
            "fr_0016_state": "SUPERSEDED_AFTER_REPAIR_BEFORE_QUALIFICATION",
            "fr_0016_authority_conferred": False,
            "fr_0016_successor_verifier_state": "RETIRED_AT_FR_0017_REPAIR",
            "fr_0016_successor_verifier_executed": False,
            "earlier_recovery_python_executed": False,
            "fr_0016_plan_namespace": FR0016_PLAN_NAMESPACE,
            "fr_0016_plan_state": "PENDING_QUALIFICATION",
            "inherited_fr_0016_defect_count": 4,
            "inherited_fr_0016_defect_source": "EXACT_SIGNED_FR_0016_PLAN",
            "prior_active_boundary": {
                "repair_commit": FR0015_REPAIR,
                "repair_tree": FR0015_REPAIR_TREE,
                "qualification_commit": FR0015_QUALIFICATION,
                "qualification_tree": FR0015_QUALIFICATION_TREE,
                "activation_commit": FR0015_ACTIVATION,
                "activation_tree": FR0015_ACTIVATION_TREE,
                "fr_0015_state": "ACTIVE_RETIRED_AT_FR_0016_REPAIR",
                "fr_0015_plan_namespace": FR0015_PLAN_NAMESPACE,
                "fr_0015_qualification_namespace": FR0015_QUALIFICATION_NAMESPACE,
                "fr_0015_activation_namespace": FR0015_ACTIVATION_NAMESPACE,
            },
            "signed_successor_chain": [
                {
                    "commit": commit,
                    "parent": parent,
                    "tree": tree,
                    "subject": subject,
                }
                for commit, parent, tree, subject in FR0015_SUCCESSORS
            ],
            "fr_0016_forbidden_completion_paths": sorted(
                FR0016_FORBIDDEN_COMPLETION_PATHS
            ),
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
            "records": copy.deepcopy(FR0016_BOUNDARY_RECORDS),
        },
        "defects": [
            {
                "id": "FR0017-D01",
                "summary": (
                    "FR-0016 main CI run 30563526669 completed supply-chain "
                    "job 90942261140 with its exact pull-request recovery "
                    "step 11 skipped, while the strict epoch-17 ordinary-step "
                    "validator required every producer step to succeed."
                ),
                "diagnostic_error": "FR0016_STEP:epoch17.ordinary.jobs.0.step.10",
                "observed_run_id": 30_563_526_669,
                "observed_job_id": 90_942_261_140,
                "observed_step_number": 11,
                "observed_step_name": (
                    "Verify epoch-17 recovery primitives on pull-request merge"
                ),
                "observed_step_status": "completed",
                "observed_step_conclusion": "skipped",
                "observation_role": "DIAGNOSIS_ONLY_NOT_AUTHORITY",
                "prior_state": "R_MAIN_CI_EVIDENCE_NOT_QUALIFIABLE",
                "required_state": (
                    "EVENT_NEUTRAL_DISPATCHER_STEP_COMPLETED_SUCCESS_EXACTLY_ONCE"
                ),
                "authority_produced": False,
            },
        ],
        "correction": {
            "normative_qualification_evidence": [
                "SIGNED_FR_0016_REPAIR_BOUNDARY_SUPERSEDED_UNQUALIFIED",
                "FR_0017_R_TEMPORARY_PR_TWO_PARENT_MERGE_ALL_REQUIRED_CHECKS",
                "FR_0017_R_MAIN_CI_RESULT_AND_GITHUB_OIDC_ATTESTATION",
                "FR_0017_R_MAIN_FORMAL_RESULT_AND_GITHUB_OIDC_ATTESTATION",
                "FR_0017_R_EXACT_LOCAL_VALIDATION",
                "SIGNED_SOURCE_AUTHORITY",
            ],
            "pull_request_mode": {
                "event": "pull_request",
                "temporary": True,
                "base_ref": "main",
                "base_commit": PARENT,
                "head_commit": "SIGNED_FR_0017_REPAIR_COMMIT",
                "checkout": "GITHUB_DEFAULT_TWO_PARENT_SYNTHETIC_MERGE",
                "synthetic_merge_parent_order": [
                    PARENT,
                    "SIGNED_FR_0017_REPAIR_COMMIT",
                ],
                "event_contract": copy.deepcopy(PULL_REQUEST_EVENT_CONTRACT),
                "run_to_pull_request_binding": (
                    "EXACT_ACTIONS_RUN_REST_PULL_REQUEST_ASSOCIATION"
                ),
                "association_capture_phase": (
                    "REQUIRED_RUNS_COMPLETE_WHILE_PULL_REQUEST_OPEN"
                ),
                "final_capture_phase": "AFTER_PULL_REQUEST_CLOSED_UNMERGED",
                "required_successful_jobs": sorted(REQUIRED_PRE_ACCEPT_CHECKS),
                "required_successful_job_count": 7,
                "trusted_event_only_surfaces_skipped": [
                    "SIGNED_LINEAR_CURRENT_AUDIT_GATE",
                    "PINNED_GITHUB_CLI_INSTALL",
                    "ISOLATED_TASK_RUNNER_IMAGE_PRELOAD",
                    "EPOCH_18_RESULT_EMIT_AND_UPLOAD",
                    "OIDC_ATTESTATION",
                ],
                "signed_linear_gate_replacement_commands": [
                    (
                        "python3 -I -B -W error "
                        "tools/release/test_verify_framework_recovery_fr_0017.py"
                    ),
                    ("python3 -I -B -W error tools/test_pinned_cargo_deny.py"),
                    "python3 -I -B -W error tools/test_run_formal.py",
                ],
                "seven_required_pre_accept_jobs_skipped": False,
                "signed_linear_current_audit_gate_skipped": True,
                "epoch_18_recovery_primitive_suite_skipped": False,
                "pinned_cargo_deny_suite_skipped": False,
                "formal_runner_suite_skipped": False,
                "full_main_gate_replayed": False,
                "final_disposition": "CLOSED_UNMERGED",
                "runtime_checkout_sha_independently_attested": False,
                "dispatcher_step": {
                    "name": ("Verify epoch-18 recovery primitives for current event"),
                    "cardinality": 1,
                    "required_status": "completed",
                    "required_conclusion": "success",
                    "pull_request_action": "RUN_THREE_EXACT_REPLACEMENT_SUITES",
                    "push_or_workflow_dispatch_action": (
                        "ACKNOWLEDGE_PRECEDING_SUCCESSFUL_CURRENT_AUDIT_GATE"
                    ),
                    "unknown_event_action": "FAIL",
                },
            },
            "main_concurrency": {
                "ci_group": (
                    "ci-${{ github.ref == 'refs/heads/main' && "
                    "github.run_id || github.ref }}"
                ),
                "formal_group": (
                    "formal-${{ github.ref == 'refs/heads/main' && "
                    "github.run_id || github.ref }}"
                ),
                "cancel_in_progress": ("${{ github.ref != 'refs/heads/main' }}"),
                "main_run_group_includes_unique_run_id": True,
                "main_cancel_in_progress": False,
                "main_run_coalescing": False,
                "non_main_cancel_in_progress": True,
            },
            "formal_toolchain": {
                "pins": copy.deepcopy(FORMAL_PIN_CONTRACT),
                "tla_tools_download": {
                    "curl_configuration_files_disabled": True,
                    "https_only": True,
                    "redirect_https_only": True,
                    "minimum_tls": "1.2",
                    "retry_count": 3,
                    "retry_all_errors": True,
                    "connect_timeout_seconds": 30,
                    "maximum_time_seconds": 300,
                    "maximum_redirects": 5,
                    "maximum_bytes": 2_274_532,
                    "exact_bytes_verified": True,
                    "sha256_verified_before_execution": True,
                },
                "java_runtime_archive": {
                    "distribution": formal_pins["java_distribution"],
                    "release_tag": formal_pins["java_release_tag"],
                    "package": formal_pins["java_archive_package"],
                    "archive_architecture": formal_pins["java_archive_architecture"],
                    "archive_name": formal_pins["java_archive_name"],
                    "archive_root": formal_pins["java_archive_root"],
                    "url": formal_pins["java_archive_url"],
                    "bytes": formal_pins["java_archive_bytes"],
                    "sha256": formal_pins["java_archive_sha256"],
                    "download": {
                        "curl_configuration_files_disabled": True,
                        "https_only": True,
                        "redirect_https_only": True,
                        "minimum_tls": "1.2",
                        "retry_count": 3,
                        "retry_all_errors": True,
                        "connect_timeout_seconds": 30,
                        "maximum_time_seconds": 300,
                        "maximum_redirects": 5,
                        "maximum_bytes": formal_pins["java_archive_bytes"],
                        "exact_bytes_verified": True,
                        "sha256_verified_before_extraction": True,
                    },
                    "safe_extraction": {
                        "fresh_private_staging_directory": True,
                        "exact_single_root": formal_pins["java_archive_root"],
                        "member_path_components_allowlisted": True,
                        "top_level_members_allowlisted": [
                            "NOTICE",
                            "bin",
                            "conf",
                            "legal",
                            "lib",
                            "release",
                        ],
                        "duplicate_members_rejected": True,
                        "allowed_member_types": [
                            "DIRECTORY",
                            "REGULAR_FILE",
                            "REVIEWED_LEGAL_SYMLINK",
                        ],
                        "archive_member_count": 320,
                        "regular_file_count": 112,
                        "directory_count": 63,
                        "reviewed_legal_symlinks": {
                            "count": 145,
                            "canonical_sorted_manifest_bytes": 13_095,
                            "canonical_sorted_manifest_sha256": (
                                "e623b66f52db07699c4723e448b1a34531097e6c38ee63630"
                                "da3dcd81729d576"
                            ),
                            "path_and_target_grammar_verified": True,
                        },
                        "unreviewed_links_and_special_files_rejected": True,
                        "legal_subtree_excluded_from_extraction": True,
                        "strip_components": 1,
                        "archive_owner_preserved": False,
                        "archive_permissions_preserved": False,
                        "post_extract_tree_types_revalidated": True,
                        "post_extract_symlinks_rejected": True,
                        "post_extract_special_files_rejected": True,
                        "directory_mode": "0700",
                        "executable_file_mode": "0700",
                        "non_executable_file_mode": "0600",
                        "java_executable_regular_non_symlink": True,
                        "java_executable_mode": "0700",
                    },
                    "runtime_property_checks": {
                        "environment_override_variables_unset": [
                            "JAVA_TOOL_OPTIONS",
                            "_JAVA_OPTIONS",
                            "JDK_JAVA_OPTIONS",
                        ],
                        "exactly_one_value_per_property": True,
                        "exact": {
                            "java.vendor": formal_pins["java_runtime_vendor"],
                            "java.runtime.version": formal_pins["java_runtime_version"],
                            "java.specification.version": formal_pins[
                                "java_specification_version"
                            ],
                            "os.arch": formal_pins["java_runtime_architecture"],
                        },
                    },
                },
                "workflow_shell": ("/bin/bash --noprofile --norc -euo pipefail {0}"),
                "workflow_command": FORMAL_WORKFLOW_COMMAND,
                "direct_java_execution": True,
                "pipeline_producer_failure_preserved": True,
            },
            "formal_pin_contract": {
                "schema_version": 3,
                "top_level_formal_key_count": 16,
                "exact": copy.deepcopy(FORMAL_PIN_CONTRACT["formal"]),
                "closed_keys_and_exact_json_types": True,
            },
            "local_formal_runtime": {
                "schema": "HALDIR_FORMAL_RUNTIME_V2",
                "recovery_evidence_consumer": False,
                "observed_architectures": list(LOCAL_FORMAL_RUNTIME_ARCHITECTURES),
                "universal_amd64_runtime_claimed": False,
                "exact_java_vendor": formal_pins["java_runtime_vendor"],
                "exact_java_runtime_version": formal_pins["java_runtime_version"],
                "hosted_archive_architecture_not_imposed_locally": True,
                "verified_tla_asset": {
                    "tla_tools_version": formal_pins["tla_tools_version"],
                    "tla_tools_bytes": formal_pins["tla_tools_bytes"],
                    "tla_tools_sha256": formal_pins["tla_tools_sha256"],
                },
            },
            "automated_paid_model_reviews": {
                "required": False,
                "normative": False,
                "authority_conferred": False,
                "reason": "NO_INDEPENDENTLY_ATTESTED_PROVIDER_PROVENANCE",
            },
            "hosted_result_transport": {
                "protocol": "HALDIR_EPOCH_18_HOSTED_RESULT_V1",
                "state": "EPOCH_18_PROVENANCE_FORMAT",
                "governance_epoch": 18,
                "authority_conferred": False,
            },
            "hosted_settings_capture": {
                "capture_method": "GET_ONLY",
                "mutation_performed": False,
                "observed_ref": "refs/heads/main",
                "observed_commit": "SIGNED_FR_0017_QUALIFICATION_COMMIT",
                "ref_stable_during_capture": True,
                "expected_policy": copy.deepcopy(HOSTED_SETTINGS_EXPECTED_POLICY),
                "history_scope": copy.deepcopy(HOSTED_SETTINGS_HISTORY_SCOPE),
                "transport": "GITHUB_API_OVER_TLS",
                "cryptographic_proof": False,
                "durable_external_state_proof": False,
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
                "fr0017_change_reason": (
                    "MAKE_RECOVERY_EVENT_DISPATCH_VISIBLE_AS_EXACT_SUCCESS_STEP"
                ),
                "inherited_immutable_action_baseline": [
                    {
                        "name": "actions/setup-python",
                        "version": "v7.0.0",
                        "commit": "5fda3b95a4ea91299a34e894583c3862153e4b97",
                    },
                    {
                        "name": "actions/attest",
                        "version": "v4.2.1",
                        "commit": "508db95dd578ae2727ebd6217d5ba78e4fbda05d",
                    },
                ],
                "formal_java_runtime_acquisition": {
                    "mode": "DIRECT_EXACT_ARCHIVE",
                    "third_party_resolver_action_uses": 0,
                    "archive_url": formal_pins["java_archive_url"],
                    "archive_bytes": formal_pins["java_archive_bytes"],
                    "archive_sha256": formal_pins["java_archive_sha256"],
                    "safe_extraction": True,
                    "runtime_properties_verified": True,
                },
                "cargo_deny_direct_execution": {
                    "state": "INHERITED_FROM_SIGNED_FR_0016_REPAIR_BOUNDARY",
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
            _fail("FR0017_LEGACY_COMPLETION_PRESENT:" + path)
    listing = _git(repo, "ls-tree", "-r", "-z", "--name-only", commit)
    try:
        tree_paths = [item.decode("utf-8") for item in listing.split(b"\0") if item]
    except UnicodeDecodeError:
        _fail("FR0017_TREE_PATH_ENCODING")
    closure_prefix = "release/0.9.0/current-head/closures/framework-recovery/fr-0016-"
    evidence_prefix = "release/0.9.0/current-head/evidence/framework-recovery-fr-0016-"
    review_prefix = "release/0.9.0/current-head/reviews/framework-recovery-fr-0016-"
    for path in tree_paths:
        folded = path.casefold()
        if (
            folded.startswith(closure_prefix)
            and path != FR0016_PLAN_PATH
            or folded.startswith(evidence_prefix)
            or folded.startswith(review_prefix)
        ):
            _fail("FR0017_FR0016_COMPLETION_LOOKALIKE:" + path)


def _verify_legacy_boundary(repo: Path) -> None:
    if _metadata(repo, PARENT)["tree"] != PARENT_TREE:
        _fail("FR0017_PARENT_TREE")
    signer_record = file_record(repo, PARENT, ALLOWED_SIGNERS_PATH)
    expected_signer = FR0016_BOUNDARY_RECORDS[ALLOWED_SIGNERS_PATH]
    if {
        key: signer_record[key]
        for key in ("git_mode", "git_object_id", "sha256", "bytes")
    } != expected_signer:
        _fail("FR0017_ALLOWED_SIGNERS_BOUNDARY")
    _verify_worktree(repo, PARENT, (ALLOWED_SIGNERS_PATH,))
    _verify_commit_identity(
        repo,
        PARENT,
        parent=PARENT_PARENT,
        subject=PARENT_SUBJECT,
    )
    if _metadata(repo, FR0015_REPAIR)["tree"] != FR0015_REPAIR_TREE:
        _fail("FR0017_FR0015_REPAIR_TREE")
    _verify_commit_identity(
        repo,
        FR0015_REPAIR,
        parent=FR0015_REPAIR_PARENT,
        subject=FR0015_REPAIR_SUBJECT,
    )
    if _metadata(repo, FR0015_QUALIFICATION)["tree"] != FR0015_QUALIFICATION_TREE:
        _fail("FR0017_FR0015_QUALIFICATION_TREE")
    _verify_commit_identity(
        repo,
        FR0015_QUALIFICATION,
        parent=FR0015_REPAIR,
        subject=FR0015_QUALIFICATION_SUBJECT,
    )
    if _metadata(repo, FR0015_ACTIVATION)["tree"] != FR0015_ACTIVATION_TREE:
        _fail("FR0017_FR0015_ACTIVATION_TREE")
    _verify_commit_identity(
        repo,
        FR0015_ACTIVATION,
        parent=FR0015_QUALIFICATION,
        subject=FR0015_ACTIVATION_SUBJECT,
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
        *FR0015_BOUNDARY_RECORDS,
        *HISTORICAL_RECOVERY_TOOL_PATHS,
    }
    for commit, parent, tree, subject in FR0015_SUCCESSORS:
        if _metadata(repo, commit)["tree"] != tree:
            _fail("FR0017_FR0015_SUCCESSOR_TREE:" + commit)
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
            _fail("FR0017_FR0015_SUCCESSOR_SCOPE:" + commit)
    for path, expected in FR0015_BOUNDARY_RECORDS.items():
        observed = file_record(repo, PARENT, path)
        comparable = {
            key: observed[key]
            for key in ("git_mode", "git_object_id", "sha256", "bytes")
        }
        if comparable != expected:
            _fail("FR0017_LEGACY_RECORD:" + path)
    for path, expected in FR0016_BOUNDARY_RECORDS.items():
        observed = file_record(repo, PARENT, path)
        comparable = {
            key: observed[key]
            for key in ("git_mode", "git_object_id", "sha256", "bytes")
        }
        if comparable != expected:
            _fail("FR0017_FR0016_RECORD:" + path)
    _assert_absent(
        repo,
        PARENT,
        sorted(
            FR0016_FORBIDDEN_COMPLETION_PATHS
            | FR0013_FORBIDDEN_COMPLETION_PATHS
            | FR0010_FORBIDDEN_COMPLETION_PATHS
            | FR0011_FORBIDDEN_COMPLETION_PATHS
            | FR0012_FORBIDDEN_COMPLETION_PATHS
        ),
    )
    plan, _payload = _read_json(repo, PARENT, FR0015_PLAN_PATH)
    if (
        plan.get("recovery_id") != "FR-0015"
        or plan.get("protocol_parent", {}).get("commit") != FR0015_REPAIR_PARENT
        or plan.get("repair_identity", {}).get("commit")
        != "SIGNED_COMMIT_CONTAINING_THIS_PLAN"
    ):
        _fail("FR0017_FR0015_PLAN_STATE")
    _validate_authority(
        plan.get("authority"),
        state="PENDING_QUALIFICATION",
        framework_epoch=16,
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
        namespace=FR0015_PLAN_NAMESPACE,
    )
    qualification, _payload = _read_json(
        repo,
        PARENT,
        FR0015_QUALIFICATION_PATH,
    )
    if (
        qualification.get("recovery_id") != "FR-0015"
        or qualification.get("stage") != "QUALIFICATION"
        or qualification.get("state_before") != "PENDING_QUALIFICATION"
        or qualification.get("state_after") != "QUALIFIED_PENDING_ACTIVATION"
        or qualification.get("repair_commit") != FR0015_REPAIR
        or qualification.get("plan_record")
        != file_record(repo, PARENT, FR0015_PLAN_PATH)
    ):
        _fail("FR0017_FR0015_QUALIFICATION_STATE")
    _validate_authority(
        qualification.get("authority"),
        state="QUALIFIED_PENDING_ACTIVATION",
        framework_epoch=16,
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
        namespace=FR0015_QUALIFICATION_NAMESPACE,
    )
    activation, _payload = _read_json(repo, PARENT, FR0015_ACTIVATION_PATH)
    if (
        activation.get("recovery_id") != "FR-0015"
        or activation.get("stage") != "ACTIVATION"
        or activation.get("state_before") != "QUALIFIED_PENDING_ACTIVATION"
        or activation.get("state_after") != "ACTIVE"
        or activation.get("repair_commit") != FR0015_REPAIR
        or activation.get("qualification_commit") != FR0015_QUALIFICATION
        or activation.get("plan_record") != file_record(repo, PARENT, FR0015_PLAN_PATH)
        or activation.get("qualification_record")
        != file_record(repo, PARENT, FR0015_QUALIFICATION_PATH)
    ):
        _fail("FR0017_FR0015_ACTIVATION_STATE")
    _validate_authority(
        activation.get("authority"),
        state="ACTIVE",
        framework_epoch=16,
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
        namespace=FR0015_ACTIVATION_NAMESPACE,
    )
    fr0016_plan, _payload = _read_json(repo, PARENT, FR0016_PLAN_PATH)
    if (
        fr0016_plan.get("schema_version") != "1.0.0"
        or fr0016_plan.get("recovery_id") != "FR-0016"
        or fr0016_plan.get("protocol_parent")
        != {"commit": PARENT_PARENT, "tree": M16_TREE}
        or fr0016_plan.get("repair_identity")
        != {
            "commit": "SIGNED_COMMIT_CONTAINING_THIS_PLAN",
            "required_parent": PARENT_PARENT,
            "subject": PARENT_SUBJECT,
        }
        or fr0016_plan.get("stage_contract", {}).get(
            "ordinary_successor_before_activation"
        )
        != "REJECT"
        or not isinstance(fr0016_plan.get("defects"), list)
        or any(not isinstance(item, dict) for item in fr0016_plan["defects"])
        or [item.get("id") for item in fr0016_plan["defects"]]
        != ["FR0016-D01", "FR0016-D02", "FR0016-D03", "FR0016-D04"]
    ):
        _fail("FR0017_FR0016_PLAN_STATE")
    _validate_authority(
        fr0016_plan.get("authority"),
        state="PENDING_QUALIFICATION",
        framework_epoch=17,
    )
    fr0016_unsigned = {
        key: copy.deepcopy(item)
        for key, item in fr0016_plan.items()
        if key != "detached_signature"
    }
    _verify_detached(
        repo,
        fr0016_plan.get("detached_signature"),
        canonical_json_bytes(fr0016_unsigned),
        namespace=FR0016_PLAN_NAMESPACE,
    )


def _verify_repair_tree(repo: Path, commit: str) -> None:
    if _changed_statuses(repo, PARENT, commit) != dict(sorted(REPAIR_STATUSES.items())):
        _fail("FR0017_REPAIR_DIFF")
    for path, mode in REPAIR_MODES.items():
        if _tree_entry(repo, commit, path)["mode"] != mode:
            _fail("FR0017_REPAIR_MODE:" + path)
    for path in FR0015_BOUNDARY_RECORDS:
        if path not in REPAIR_STATUSES and _tree_entry(
            repo, commit, path
        ) != _tree_entry(repo, PARENT, path):
            _fail("FR0017_LEGACY_DRIFT:" + path)
    for path in FR0016_BOUNDARY_RECORDS:
        if path not in REPAIR_STATUSES and _tree_entry(
            repo, commit, path
        ) != _tree_entry(repo, PARENT, path):
            _fail("FR0017_FR0016_DRIFT:" + path)
    _assert_absent(
        repo,
        commit,
        sorted(
            FR0016_FORBIDDEN_COMPLETION_PATHS
            | FR0013_FORBIDDEN_COMPLETION_PATHS
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
        _fail("FR0017_PLAN_INVALID")
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
        _fail("FR0017_MODULE_WORKTREE_DRIFT")
    if current != payload:
        _fail("FR0017_MODULE_WORKTREE_DRIFT")
    specification = importlib.util.spec_from_file_location(
        "_haldir_fr0017_protocol", repo / MODULE_PATH
    )
    if specification is None or specification.loader is None:
        _fail("FR0017_MODULE_LOAD")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    if (
        module.RESULT_PROTOCOL != "HALDIR_EPOCH_18_HOSTED_RESULT_V1"
        or module.MAX_EPOCH18_RUN_ATTEMPT != 8
    ):
        _fail("FR0017_MODULE_CONTRACT")
    return module


def _evidence_catalog(
    repo: Path, commit: str, paths: Sequence[str]
) -> list[dict[str, Any]]:
    return [file_record(repo, commit, path) for path in paths]


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("FR0017_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("FR0017_TIMESTAMP:" + label)
    if parsed.tzinfo != timezone.utc:
        _fail("FR0017_TIMESTAMP:" + label)
    return parsed


def _parse_git_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        _fail("FR0017_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _fail("FR0017_TIMESTAMP:" + label)
    if parsed.tzinfo is None:
        _fail("FR0017_TIMESTAMP:" + label)
    return parsed.astimezone(timezone.utc)


def _bounded_file_sha256(path: Path, *, expected_bytes: int) -> str:
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > expected_bytes:
                _fail("FR0017_GH_EXECUTABLE")
            digest.update(chunk)
    if consumed != expected_bytes:
        _fail("FR0017_GH_EXECUTABLE")
    return digest.hexdigest()


def _trusted_gh() -> tuple[Path, str]:
    if sys.platform == "darwin":
        expected_binary_bytes = GH_CLI_MACOS_ARM64_BINARY_BYTES
        expected_binary_sha256 = GH_CLI_MACOS_ARM64_BINARY_SHA256
    elif sys.platform.startswith("linux"):
        expected_binary_bytes = GH_CLI_LINUX_AMD64_BINARY_BYTES
        expected_binary_sha256 = GH_CLI_LINUX_AMD64_BINARY_SHA256
    else:
        _fail("FR0017_GH_EXECUTABLE")
    configured = os.environ.get("HALDIR_FR0017_GH")
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
                _fail("FR0017_GH_EXECUTABLE")
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
        _fail("FR0017_GH_EXECUTABLE")
    with tempfile.TemporaryDirectory(prefix="haldir-fr0017-gh-version-") as name:
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
        _fail("FR0017_GH_VERSION")
    try:
        output = completed.stdout.decode("ascii")
    except UnicodeDecodeError:
        _fail("FR0017_GH_VERSION")
    if not output.startswith("gh version 2.96.0 (2026-07-02)\n"):
        _fail("FR0017_GH_VERSION")
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
                _fail("FR0017_TEMP_WRITE")
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
        _fail("FR0017_PROCESS_BOUND")
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
            failure = "FR0017_PROCESS_PIPE"
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
                        "FR0017_PROCESS_CLEANUP"
                        if leader_exited
                        else "FR0017_PROCESS_TIMEOUT"
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
                        failure = "FR0017_PROCESS_OUTPUT_BOUND"
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
                    failure = "FR0017_PROCESS_TIMEOUT"
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
                    failure = "FR0017_PROCESS_REAP"
    except Exception:
        failure = "FR0017_PROCESS_CLEANUP"
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
        _fail("FR0017_PROCESS_CLEANUP")
    if unexpected is not None:
        raise unexpected
    if failure is not None:
        _fail(failure)
    if returncode is None or streams is None:
        _fail("FR0017_PROCESS_REAP")
    return returncode, bytes(streams["stdout"]), bytes(streams["stderr"])


def _validate_trusted_root(payload: bytes) -> None:
    if (
        len(payload) != TRUSTED_ROOT_BYTES
        or hashlib.sha256(payload).hexdigest() != TRUSTED_ROOT_SHA256
        or b"\0" in payload
        or not payload.endswith(b"\n")
    ):
        _fail("FR0017_TRUSTED_ROOT_BOUND")
    lines = payload.splitlines()
    if len(lines) != 1:
        _fail("FR0017_TRUSTED_ROOT_BOUND")
    try:
        value = json.loads(lines[0])
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0017_TRUSTED_ROOT_JSONL")
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
        _fail("FR0017_TRUSTED_ROOT_IDENTITY")


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
    with tempfile.TemporaryDirectory(prefix="haldir-fr0017-attestation-") as name:
        root = Path(name)
        result_path = root / f"epoch-18-{workflow}-result-attempt-{attempt}.json"
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
        _fail("FR0017_ATTESTATION_CRYPTOGRAPHY")
    try:
        receipt = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0017_ATTESTATION_CRYPTOGRAPHY")
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
    artifact_name = f"epoch-18-{workflow}-result-attempt-{attempt}.json"
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
        or capture["protocol"] != "HALDIR_FR_0017_HOSTED_RESULT_CAPTURE_V1"
        or capture["workflow"] != workflow
        or capture["subject_commit"] != subject_commit
        or capture["subject_tree"] != _metadata(repo, subject_commit)["tree"]
        or capture["expected_ref"] != "refs/heads/main"
        or capture["result"] != "PASS"
        or capture["capture_tool"] != file_record(repo, repair_commit, CAPTURE_PATH)
    ):
        _fail("FR0017_HOSTED_CAPTURE_SCHEMA")
    if capture["result_record"] != file_record(repo, containing_commit, paths[1]):
        _fail("FR0017_HOSTED_RESULT_RECORD")
    if capture["attestation_record"] != file_record(repo, containing_commit, paths[2]):
        _fail("FR0017_HOSTED_ATTESTATION_RECORD")
    if capture["trusted_root_record"] != file_record(
        repo, repair_commit, TRUSTED_ROOT_PATH
    ):
        _fail("FR0017_HOSTED_TRUSTED_ROOT_RECORD")
    _validate_trusted_root(trusted_root_payload)
    run = protocol.validate_epoch18_run_documents(
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
        _fail("FR0017_ARTIFACT_UNIQUENESS")
    if capture["artifact_download"] != {
        "bytes": len(result_payload),
        "content_mode": "DIRECT_UNARCHIVED_FILE",
        "sha256": hashlib.sha256(result_payload).hexdigest(),
    }:
        _fail("FR0017_ARTIFACT_DOWNLOAD")
    artifact = capture["artifact"]
    artifact_id = artifact.get("id", 0) if isinstance(artifact, dict) else 0
    if capture["commands"] != _hosted_commands(
        workflow=workflow,
        run_id=run["run_id"],
        attempt=run["attempt"],
        artifact_id=artifact_id,
    ):
        _fail("FR0017_HOSTED_COMMANDS")
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
        _fail("FR0017_HOSTED_CHRONOLOGY")
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
        _fail("FR0017_CAPTURE_OFFLINE_VERIFICATION")
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
        _fail("FR0017_REPOSITORY_IDENTITY")
    return copy.deepcopy(value)


def _parse_api_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        _fail("FR0017_API_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("FR0017_API_TIMESTAMP:" + label)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("FR0017_API_TIMESTAMP:" + label)
    return parsed


def _pull_request_open_capture_commands(
    *,
    number: int,
    merge_commit: str,
    ci_run_id: int,
    formal_run_id: int,
) -> dict[str, str]:
    fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,"
        "jobs,number,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    return {
        "repository": f"gh api --method GET repos/{REPOSITORY_FULL_NAME}",
        "pull_request": (
            f"gh api --method GET repos/{REPOSITORY_FULL_NAME}/pulls/{number}"
        ),
        "merge_commit": (
            f"gh api --method GET repos/{REPOSITORY_FULL_NAME}/git/commits/"
            f"{merge_commit}"
        ),
        "ci_run": (
            f"gh run view {ci_run_id} --repo {REPOSITORY_FULL_NAME} --json {fields}"
        ),
        "ci_run_pull_request": (
            f"gh api --method GET repos/{REPOSITORY_FULL_NAME}/actions/runs/{ci_run_id}"
        ),
        "formal_run": (
            f"gh run view {formal_run_id} --repo {REPOSITORY_FULL_NAME} --json {fields}"
        ),
        "formal_run_pull_request": (
            f"gh api --method GET repos/{REPOSITORY_FULL_NAME}/actions/runs/"
            f"{formal_run_id}"
        ),
    }


def _pull_request_capture_commands(
    *,
    number: int,
    merge_commit: str,
    ci_run_id: int,
    formal_run_id: int,
) -> dict[str, str]:
    open_commands = _pull_request_open_capture_commands(
        number=number,
        merge_commit=merge_commit,
        ci_run_id=ci_run_id,
        formal_run_id=formal_run_id,
    )
    fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,"
        "jobs,number,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    return {
        **{f"open_{name}": command for name, command in open_commands.items()},
        "closed_repository": (f"gh api --method GET repos/{REPOSITORY_FULL_NAME}"),
        "closed_pull_request": (
            f"gh api --method GET repos/{REPOSITORY_FULL_NAME}/pulls/{number}"
        ),
        "closed_merge_commit": (
            f"gh api --method GET repos/{REPOSITORY_FULL_NAME}/git/commits/"
            f"{merge_commit}"
        ),
        "closed_ci_run": (
            f"gh run view {ci_run_id} --repo {REPOSITORY_FULL_NAME} --json {fields}"
        ),
        "closed_formal_run": (
            f"gh run view {formal_run_id} --repo {REPOSITORY_FULL_NAME} --json {fields}"
        ),
    }


def _validate_run_pull_request_association(
    value: Any,
    *,
    run_id: int,
    number: int,
    database_id: int,
    head_ref: str,
    repair_commit: str,
) -> dict[str, Any]:
    expected = {
        "run_id": run_id,
        "run_api_url": (
            f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/actions/runs/{run_id}"
        ),
        "pull_request": {
            "number": number,
            "database_id": database_id,
            "api_url": (
                f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/pulls/{number}"
            ),
            "head": {
                "ref": head_ref,
                "sha": repair_commit,
                "repository_id": REPOSITORY_ID,
            },
            "base": {
                "ref": "main",
                "sha": PARENT,
                "repository_id": REPOSITORY_ID,
            },
        },
    }
    pull_request = value.get("pull_request") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"pull_request", "run_api_url", "run_id"}
        or type(value.get("run_id")) is not int
        or not isinstance(pull_request, dict)
        or set(pull_request) != {"api_url", "base", "database_id", "head", "number"}
        or type(pull_request.get("number")) is not int
        or type(pull_request.get("database_id")) is not int
        or value != expected
    ):
        _fail("FR0017_PULL_REQUEST_RUN_ASSOCIATION")
    return copy.deepcopy(value)


def validate_pull_request_evidence(
    repo: Path,
    value: Any,
    *,
    repair_commit: str,
    containing_commit: str,
    protocol: ModuleType,
) -> dict[str, Any]:
    """Validate the closed, unmerged temporary-PR qualification record."""

    expected_fields = {
        "authority",
        "capture",
        "github_event_contract",
        "protocol",
        "pull_request",
        "repository",
        "runs",
        "run_pull_request_associations",
        "schema_version",
        "synthetic_merge",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or value["schema_version"] != "1.0.0"
        or value["protocol"] != "HALDIR_FR_0017_PULL_REQUEST_QUALIFICATION_V1"
    ):
        _fail("FR0017_PULL_REQUEST_SCHEMA")
    validate_repository_identity(value["repository"])
    pull_request = value["pull_request"]
    pull_fields = {
        "api_url",
        "base",
        "closed_at",
        "created_at",
        "database_id",
        "draft",
        "head",
        "html_url",
        "locked",
        "merge_commit_sha",
        "merged",
        "merged_at",
        "node_id",
        "number",
        "state",
        "updated_at",
    }
    if not isinstance(pull_request, dict) or set(pull_request) != pull_fields:
        _fail("FR0017_PULL_REQUEST_RECORD")
    number = pull_request["number"]
    database_id = pull_request["database_id"]
    node_id = pull_request["node_id"]
    merge_commit = pull_request["merge_commit_sha"]
    if (
        type(number) is not int
        or not 1 <= number <= 2**63 - 1
        or type(database_id) is not int
        or not 1 <= database_id <= 2**63 - 1
        or not isinstance(node_id, str)
        or not node_id
        or len(node_id) > 256
        or not isinstance(merge_commit, str)
        or HEX40.fullmatch(merge_commit) is None
        or pull_request["api_url"]
        != f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/pulls/{number}"
        or pull_request["html_url"]
        != f"https://github.com/{REPOSITORY_FULL_NAME}/pull/{number}"
        or pull_request["state"] != "closed"
        or type(pull_request["draft"]) is not bool
        or pull_request["draft"] is not False
        or type(pull_request["locked"]) is not bool
        or pull_request["locked"] is not False
        or type(pull_request["merged"]) is not bool
        or pull_request["merged"] is not False
        or pull_request["merged_at"] is not None
    ):
        _fail("FR0017_PULL_REQUEST_RECORD")
    head = pull_request["head"]
    base = pull_request["base"]
    ref_fields = {"ref", "repository_id", "sha"}
    if (
        not isinstance(head, dict)
        or set(head) != ref_fields
        or not isinstance(base, dict)
        or set(base) != ref_fields
        or type(head["repository_id"]) is not int
        or type(base["repository_id"]) is not int
        or head["repository_id"] != REPOSITORY_ID
        or base["repository_id"] != REPOSITORY_ID
        or head["sha"] != repair_commit
        or base != {"ref": "main", "sha": PARENT, "repository_id": REPOSITORY_ID}
        or not isinstance(head["ref"], str)
        or re.fullmatch(r"[A-Za-z0-9._/-]+", head["ref"]) is None
        or len(head["ref"].encode("ascii")) > 255
        or head["ref"].startswith("/")
        or head["ref"].endswith("/")
        or ".." in head["ref"]
        or "//" in head["ref"]
        or head["ref"] == "main"
    ):
        _fail("FR0017_PULL_REQUEST_REFS")
    created = _parse_utc(pull_request["created_at"], "pull_request.created")
    updated = _parse_utc(pull_request["updated_at"], "pull_request.updated")
    closed = _parse_utc(pull_request["closed_at"], "pull_request.closed")
    if not created <= closed <= updated:
        _fail("FR0017_PULL_REQUEST_CHRONOLOGY")
    synthetic_merge = value["synthetic_merge"]
    merge_fields = {"api_url", "parents", "sha", "tree"}
    expected_parent_urls = [
        f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/git/commits/{PARENT}",
        (
            f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/git/commits/"
            f"{repair_commit}"
        ),
    ]
    if (
        not isinstance(synthetic_merge, dict)
        or set(synthetic_merge) != merge_fields
        or synthetic_merge["sha"] != merge_commit
        or synthetic_merge["api_url"]
        != (
            f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/git/commits/"
            f"{merge_commit}"
        )
        or not isinstance(synthetic_merge["tree"], str)
        or HEX40.fullmatch(synthetic_merge["tree"]) is None
        or synthetic_merge["parents"]
        != [
            {"sha": PARENT, "url": expected_parent_urls[0]},
            {"sha": repair_commit, "url": expected_parent_urls[1]},
        ]
    ):
        _fail("FR0017_PULL_REQUEST_MERGE")
    runs = value["runs"]
    if not isinstance(runs, dict) or set(runs) != {"ci", "formal"}:
        _fail("FR0017_PULL_REQUEST_RUNS")
    validated_runs = {
        workflow: protocol.validate_pull_request_run_document(
            runs[workflow],
            workflow=workflow,
            subject_commit=repair_commit,
            head_branch=head["ref"],
        )
        for workflow in ("ci", "formal")
    }
    run_ids = {item["run_id"] for item in validated_runs.values()}
    if len(run_ids) != 2:
        _fail("FR0017_PULL_REQUEST_RUNS")
    association_capture = value["run_pull_request_associations"]
    if not isinstance(association_capture, dict) or set(association_capture) != {
        "captured_at_utc",
        "ci",
        "formal",
        "observed_pull_request",
    }:
        _fail("FR0017_PULL_REQUEST_RUN_ASSOCIATION")
    observed_pull_request = association_capture["observed_pull_request"]
    if (
        not isinstance(observed_pull_request, dict)
        or set(observed_pull_request) != pull_fields
        or observed_pull_request.get("state") != "open"
        or type(observed_pull_request.get("draft")) is not bool
        or observed_pull_request["draft"] is not False
        or type(observed_pull_request.get("locked")) is not bool
        or observed_pull_request["locked"] is not False
        or type(observed_pull_request.get("merged")) is not bool
        or observed_pull_request["merged"] is not False
        or observed_pull_request.get("closed_at") is not None
        or observed_pull_request.get("merged_at") is not None
        or any(
            observed_pull_request[field] != pull_request[field]
            for field in pull_fields - {"closed_at", "state", "updated_at"}
        )
    ):
        _fail("FR0017_PULL_REQUEST_OPEN_OBSERVATION")
    open_updated = _parse_utc(
        observed_pull_request["updated_at"],
        "pull_request.open_updated",
    )
    association_captured = _parse_utc(
        association_capture["captured_at_utc"],
        "pull_request.association_captured",
    )
    if not created <= open_updated <= association_captured <= closed:
        _fail("FR0017_PULL_REQUEST_OPEN_CHRONOLOGY")
    for workflow in ("ci", "formal"):
        _validate_run_pull_request_association(
            association_capture[workflow],
            run_id=validated_runs[workflow]["run_id"],
            number=number,
            database_id=database_id,
            head_ref=head["ref"],
            repair_commit=repair_commit,
        )
        if validated_runs[workflow]["updated"] > association_captured:
            _fail("FR0017_PULL_REQUEST_OPEN_CHRONOLOGY")
    for run in validated_runs.values():
        if run["created"] < created or run["updated"] > closed:
            _fail("FR0017_PULL_REQUEST_RUN_CHRONOLOGY")
    github_event_contract = value["github_event_contract"]
    expected_event_contract = PULL_REQUEST_EVENT_CONTRACT
    if (
        not isinstance(github_event_contract, dict)
        or set(github_event_contract) != set(expected_event_contract)
        or type(github_event_contract.get("workflow_checkout_ref_override")) is not bool
        or github_event_contract != expected_event_contract
    ):
        _fail("FR0017_PULL_REQUEST_EVENT_CONTRACT")
    capture = value["capture"]
    if (
        not isinstance(capture, dict)
        or set(capture) != {"captured_at_utc", "commands", "result", "transport"}
        or capture["commands"]
        != _pull_request_capture_commands(
            number=number,
            merge_commit=merge_commit,
            ci_run_id=validated_runs["ci"]["run_id"],
            formal_run_id=validated_runs["formal"]["run_id"],
        )
        or capture["result"] != "PASS"
        or capture["transport"] != "GITHUB_API_OVER_TLS"
    ):
        _fail("FR0017_PULL_REQUEST_CAPTURE")
    captured = _parse_utc(capture["captured_at_utc"], "pull_request.captured")
    if captured < closed or captured > _parse_git_time(
        _metadata(repo, containing_commit)["committer_date"],
        "pull_request.containing_commit",
    ):
        _fail("FR0017_PULL_REQUEST_CAPTURE_CHRONOLOGY")
    expected_authority = {
        "durable_external_state_proof": False,
        "merge_commit_signature_claimed": False,
        "release_authority": False,
        "transport_observation": "GITHUB_API_OVER_TLS",
    }
    authority = value["authority"]
    if (
        not isinstance(authority, dict)
        or set(authority) != set(expected_authority)
        or type(authority.get("durable_external_state_proof")) is not bool
        or type(authority.get("merge_commit_signature_claimed")) is not bool
        or type(authority.get("release_authority")) is not bool
        or authority != expected_authority
    ):
        _fail("FR0017_PULL_REQUEST_AUTHORITY")
    return copy.deepcopy(value)


def _hosted_settings_capture_commands() -> dict[str, str]:
    base = f"repos/{REPOSITORY_FULL_NAME}"
    return {
        "actions_permissions": (f"gh api --method GET {base}/actions/permissions"),
        "dependabot_security_updates": (
            f"gh api --method GET {base}/automated-security-fixes"
        ),
        "fork_pull_request_contributor_approval": (
            f"gh api --method GET {base}/actions/permissions/"
            "fork-pr-contributor-approval"
        ),
        "main_ref_after": f"gh api --method GET {base}/git/ref/heads/main",
        "main_ref_before": f"gh api --method GET {base}/git/ref/heads/main",
        "private_vulnerability_reporting": (
            f"gh api --method GET {base}/private-vulnerability-reporting"
        ),
        "repository": f"gh api --method GET {base}",
        "selected_actions": (
            f"gh api --method GET {base}/actions/permissions/selected-actions"
        ),
        "vulnerability_alerts": (
            f"gh api --method GET --include {base}/vulnerability-alerts"
        ),
        "workflow_permissions": (
            f"gh api --method GET {base}/actions/permissions/workflow"
        ),
    }


def validate_hosted_settings_capture(
    repo: Path,
    value: Any,
    *,
    qualification_commit: str,
    containing_commit: str,
) -> dict[str, Any]:
    """Validate the exact activation-time hosted-settings observation."""

    fields = {
        "authority",
        "capture",
        "history_scope",
        "observed_commit",
        "protocol",
        "ref_after",
        "ref_before",
        "repository",
        "schema_version",
        "settings",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value["schema_version"] != "1.0.0"
        or value["protocol"] != "HALDIR_FR_0017_HOSTED_SETTINGS_CAPTURE_V1"
        or value["observed_commit"] != qualification_commit
    ):
        _fail("FR0017_HOSTED_SETTINGS_SCHEMA")
    validate_repository_identity(value["repository"])
    ref_url = f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/git/refs/heads/main"
    expected_ref = {
        "ref": "refs/heads/main",
        "node_id": value["ref_before"].get("node_id")
        if isinstance(value["ref_before"], dict)
        else None,
        "url": ref_url,
        "object": {
            "sha": qualification_commit,
            "type": "commit",
            "url": (
                f"https://api.github.com/repos/{REPOSITORY_FULL_NAME}/git/"
                f"commits/{qualification_commit}"
            ),
        },
    }
    if (
        not isinstance(expected_ref["node_id"], str)
        or not expected_ref["node_id"]
        or len(expected_ref["node_id"]) > 256
        or value["ref_before"] != expected_ref
        or value["ref_after"] != expected_ref
    ):
        _fail("FR0017_HOSTED_SETTINGS_HEAD_STABILITY")
    settings = value["settings"]
    expected_settings = HOSTED_SETTINGS_EXPECTED_POLICY
    boolean_paths = (
        ("actions_permissions", "enabled"),
        ("actions_permissions", "sha_pinning_required"),
        ("dependabot_security_updates", "enabled"),
        ("dependabot_security_updates", "paused"),
        ("private_vulnerability_reporting", "enabled"),
        ("selected_actions", "github_owned_allowed"),
        ("selected_actions", "verified_allowed"),
        ("vulnerability_alerts", "enabled"),
        ("workflow_permissions", "can_approve_pull_request_reviews"),
    )
    if (
        not isinstance(settings, dict)
        or set(settings) != set(expected_settings)
        or any(
            not isinstance(settings.get(group), dict)
            or type(settings[group].get(name)) is not bool
            for group, name in boolean_paths
        )
        or not isinstance(settings.get("vulnerability_alerts"), dict)
        or type(settings["vulnerability_alerts"].get("http_status")) is not int
        or settings != expected_settings
    ):
        _fail("FR0017_HOSTED_SETTINGS_POLICY")
    history_scope = value["history_scope"]
    expected_history_scope = HOSTED_SETTINGS_HISTORY_SCOPE
    if (
        not isinstance(history_scope, dict)
        or set(history_scope) != set(expected_history_scope)
        or type(history_scope.get("activation_commit_self_observed")) is not bool
        or type(history_scope.get("durable_historical_transition_proof")) is not bool
        or type(history_scope.get("settings_transition_time_claimed")) is not bool
        or history_scope != expected_history_scope
    ):
        _fail("FR0017_HOSTED_SETTINGS_HISTORY_SCOPE")
    capture = value["capture"]
    if (
        not isinstance(capture, dict)
        or set(capture) != {"captured_at_utc", "commands", "result", "transport"}
        or capture["commands"] != _hosted_settings_capture_commands()
        or capture["result"] != "PASS"
        or capture["transport"] != "GITHUB_API_OVER_TLS"
    ):
        _fail("FR0017_HOSTED_SETTINGS_CAPTURE")
    captured = _parse_utc(capture["captured_at_utc"], "hosted_settings.captured")
    if captured < _parse_git_time(
        _metadata(repo, qualification_commit)["committer_date"],
        "hosted_settings.qualification",
    ) or captured > _parse_git_time(
        _metadata(repo, containing_commit)["committer_date"],
        "hosted_settings.containing",
    ):
        _fail("FR0017_HOSTED_SETTINGS_CHRONOLOGY")
    expected_authority = {
        "cryptographic_proof": False,
        "durable_external_state_proof": False,
        "release_authority": False,
        "transport_observation": "GITHUB_API_OVER_TLS",
    }
    authority = value["authority"]
    if (
        not isinstance(authority, dict)
        or set(authority) != set(expected_authority)
        or type(authority.get("cryptographic_proof")) is not bool
        or type(authority.get("durable_external_state_proof")) is not bool
        or type(authority.get("release_authority")) is not bool
        or authority != expected_authority
    ):
        _fail("FR0017_HOSTED_SETTINGS_AUTHORITY")
    return copy.deepcopy(value)


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
        _fail("FR0017_RULESET_SCHEMA")
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
        _fail("FR0017_RULESET_SUMMARY")
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
        _fail("FR0017_RULESET_SUMMARY")
    created = _parse_api_timestamp(summary["created_at"], "ruleset.created")
    updated = _parse_api_timestamp(summary["updated_at"], "ruleset.updated")
    if created > updated:
        _fail("FR0017_RULESET_CHRONOLOGY")
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
        _fail("FR0017_RULESET_DETAIL")
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
        _fail("FR0017_RULESET_EFFECTIVE")
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
        _fail("FR0017_RULESET_HISTORY")
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
        _fail("FR0017_RULESET_VERSION")
    history_updated = _parse_api_timestamp(
        history_item["updated_at"],
        "ruleset.history.updated",
    )
    if history_updated < updated:
        _fail("FR0017_RULESET_CHRONOLOGY")
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
        _fail("FR0017_BRANCH_PROTECTION_POLICY")
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
        _fail("FR0017_BRANCH_PROTECTION_POLICY")
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
        or value["protocol"] != "HALDIR_FR_0017_BRANCH_PROTECTION_CAPTURE_V1"
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
        _fail("FR0017_BRANCH_PROTECTION_SCHEMA")
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
        _fail("FR0017_BRANCH_PROTECTION_HEAD_STABILITY")
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
        _fail("FR0017_BRANCH_PROTECTION_CAPTURE")
    captured = _parse_utc(capture["captured_at_utc"], "branch-protection.captured")
    if captured < _parse_git_time(
        _metadata(repo, qualification_commit)["committer_date"],
        "branch-protection.qualification",
    ) or captured > _parse_git_time(
        _metadata(repo, containing_commit)["committer_date"],
        "branch-protection.containing",
    ):
        _fail("FR0017_BRANCH_PROTECTION_CHRONOLOGY")
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
        _fail("FR0017_LOCAL_CHECK")
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
        _fail("FR0017_LOCAL_CARGO")
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
            FORMAL_RUNNER_TEST_PATH,
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
        or local["protocol"] != "HALDIR_FR_0017_LOCAL_VALIDATION_V1"
        or local["subject_commit"] != repair_commit
        or local["subject_tree"] != _metadata(repo, repair_commit)["tree"]
        or local["capture_tool"] != file_record(repo, repair_commit, CAPTURE_PATH)
        or local["python"] != {"implementation": "cpython", "version": "3.14.6"}
        or not isinstance(local["cargo"], dict)
        or not isinstance(local["checks"], list)
        or len(local["checks"]) != 8
        or local["result"] != "PASS"
        or local["authority"] != _authority("PENDING_QUALIFICATION")
    ):
        _fail("FR0017_LOCAL_EVIDENCE")
    _validate_local_cargo_record(local["cargo"])
    _validate_authority(
        local["authority"],
        state="PENDING_QUALIFICATION",
    )
    for index, check in enumerate(local["checks"]):
        _validate_local_check(check)
        if index < 6:
            executable = check["argv"][0] if check["argv"] else None
            if (
                not isinstance(executable, str)
                or not Path(executable).is_absolute()
                or not Path(executable).name.startswith("python3")
                or check["argv"][1:] != python_commands[index]
            ):
                _fail("FR0017_LOCAL_COMMAND")
        elif index == 6 and check["argv"] != [
            "/bin/bash",
            "-n",
            GATE_PATH,
        ]:
            _fail("FR0017_LOCAL_COMMAND")
        elif index == 7 and check["argv"] != [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "diff",
            "--check",
            f"{PARENT}..{repair_commit}",
        ]:
            _fail("FR0017_LOCAL_COMMAND")
    completed = _parse_utc(local["completed_at_utc"], "local.completed")
    if completed > _parse_git_time(
        _metadata(repo, containing_commit)["committer_date"],
        "local.containing_commit",
    ):
        _fail("FR0017_LOCAL_CHRONOLOGY")
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
        _fail("FR0017_QUALIFICATION_DIFF")
    for path in (QUALIFICATION_PATH, *QUALIFICATION_EVIDENCE_PATHS):
        if _tree_entry(repo, commit, path)["mode"] != "100644":
            _fail("FR0017_QUALIFICATION_MODE:" + path)
    for path in (
        *CORE_PATHS,
        PLAN_PATH,
        *FR0016_BOUNDARY_RECORDS,
        *FR0015_BOUNDARY_RECORDS,
    ):
        if _tree_entry(repo, commit, path) != _tree_entry(repo, repair_commit, path):
            _fail("FR0017_QUALIFICATION_DRIFT:" + path)
    _assert_absent(
        repo,
        commit,
        sorted(
            FR0016_FORBIDDEN_COMPLETION_PATHS
            | FR0013_FORBIDDEN_COMPLETION_PATHS
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
    pull_request_record, _payload = _read_json(
        repo,
        commit,
        PULL_REQUEST_PATH,
    )
    pull_request = validate_pull_request_evidence(
        repo,
        pull_request_record,
        repair_commit=repair_commit,
        containing_commit=commit,
        protocol=protocol,
    )
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
        "pull_request_qualification": pull_request,
        "legacy_recovery_states": {
            "FR-0010": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0011": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0012": "ABORTED_BEFORE_QUALIFICATION",
            "FR-0013": "SUPERSEDED_AFTER_QUALIFICATION_BEFORE_ACTIVATION",
            "FR-0014": "ACTIVE_RETIRED_AT_FR_0015_REPAIR",
            "FR-0015": "ACTIVE_RETIRED_AT_FR_0016_REPAIR",
            "FR-0016": "SUPERSEDED_AFTER_REPAIR_BEFORE_QUALIFICATION",
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
        _fail("FR0017_QUALIFICATION_RECORD")
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
        _fail("FR0017_ACTIVATION_DIFF")
    for path in (ACTIVATION_PATH, *ACTIVATION_EVIDENCE_PATHS):
        if _tree_entry(repo, commit, path)["mode"] != "100644":
            _fail("FR0017_ACTIVATION_MODE:" + path)
    for path in (
        *CORE_PATHS,
        PLAN_PATH,
        QUALIFICATION_PATH,
        *QUALIFICATION_EVIDENCE_PATHS,
        *FR0016_BOUNDARY_RECORDS,
        *FR0015_BOUNDARY_RECORDS,
    ):
        if _tree_entry(repo, commit, path) != _tree_entry(
            repo, qualification_commit, path
        ):
            _fail("FR0017_ACTIVATION_DRIFT:" + path)
    _assert_absent(
        repo,
        commit,
        sorted(
            FR0016_FORBIDDEN_COMPLETION_PATHS
            | FR0013_FORBIDDEN_COMPLETION_PATHS
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
    hosted_settings_record, _payload = _read_json(
        repo,
        commit,
        HOSTED_SETTINGS_PATH,
    )
    hosted_settings = validate_hosted_settings_capture(
        repo,
        hosted_settings_record,
        qualification_commit=qualification_commit,
        containing_commit=commit,
    )
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
        "hosted_settings": hosted_settings,
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
            "FR-0015": "ACTIVE_RETIRED_AT_FR_0016_REPAIR",
            "FR-0016": "SUPERSEDED_AFTER_REPAIR_BEFORE_QUALIFICATION",
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
        _fail("FR0017_ACTIVATION_RECORD")
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
            _fail("FR0017_SUCCESSOR_SCOPE")
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
            _fail("FR0017_WORKTREE:" + path)
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
            _fail("FR0017_WORKTREE:" + path)


def verify(repo: Path) -> dict[str, Any]:
    """Verify the current first-parent epoch-18 state."""

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
        _fail("FR0017_PARENT_ANCESTRY")
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
        _fail("FR0017_REPAIR_MISSING")
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
        FORMAL_README_PATH,
        JUSTFILE_PATH,
        PLAN_PATH,
        *FR0016_BOUNDARY_RECORDS,
        *FR0015_BOUNDARY_RECORDS,
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
            FR0016_FORBIDDEN_COMPLETION_PATHS
            | FR0013_FORBIDDEN_COMPLETION_PATHS
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
        _fail("FR0017_PROVISIONAL_PARENT")
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
            _fail("FR0017_PROVISIONAL_PARENT")
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
    _fail("FR0017_PROVISIONAL_STAGE")


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
        _fail("FR0017_REPOSITORY")
    try:
        return Path(completed.stdout.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _fail("FR0017_REPOSITORY")


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
        print(f"verify-framework-recovery-fr-0017: {error}", file=sys.stderr)
        return 1
    print(
        "verify-framework-recovery-fr-0017: OK "
        f"({result['state']}; epoch 18; release NO_GO)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
