#!/usr/bin/env python3
"""Offline verifier for deterministic supplemental task evidence."""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("generate-task-evidence.py")
SPEC = importlib.util.spec_from_file_location("generate_task_evidence", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery failure
    raise RuntimeError("cannot load evidence verifier core")
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)

GENERATED_RECORD = re.compile(r"^t[0-9]{3}-generated-verification\.json$")


def reconcile_all(repo: Path) -> list[dict[str, object]]:
    """Reconcile ledger supplements with every generated evidence file."""

    requirements = CORE._load_json_bytes(
        CORE._read_bounded(
            repo / "release/0.9.0/requirements.json",
            CORE.MAX_RECORD_BYTES,
            "requirements",
        ),
        "requirements",
    )
    tasks = requirements.get("tasks")
    if not isinstance(tasks, list):
        raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_TASKS_INVALID")
    entries: dict[str, dict[str, object]] = {}
    t002_status: object = None
    task_ids: set[str] = set()
    for task in tasks:
        if not isinstance(task, dict) or not isinstance(task.get("id"), str):
            raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_TASK_INVALID")
        task_id = task["id"]
        if task_id in task_ids:
            raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_TASK_DUPLICATE")
        task_ids.add(task_id)
        if task_id == "T002":
            t002_status = task.get("status")
        evidence = task.get("evidence")
        if not isinstance(evidence, list):
            raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_ITEMS_INVALID")
        for item in evidence:
            if not isinstance(item, dict):
                raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_ITEM_INVALID")
            path = item.get("path")
            generated_path = isinstance(path, str) and "-generated-" in Path(path).name
            if item.get("kind") != "generated_exact_commit_verification":
                if generated_path:
                    raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_GENERATED_KIND_INVALID")
                continue
            if (
                set(item)
                != {"kind", "path", "implementation_commit", "evidence_tool_commit"}
                or not isinstance(path, str)
                or path
                != f"{CORE.EVIDENCE_DIRECTORY}/{task_id.lower()}-generated-verification.json"
                or CORE.HEX40.fullmatch(str(item.get("implementation_commit"))) is None
                or CORE.HEX40.fullmatch(str(item.get("evidence_tool_commit"))) is None
                or path in entries
                or task.get("status") != "verified"
            ):
                raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_GENERATED_ENTRY_INVALID")
            entries[path] = item
    t002_path = f"{CORE.EVIDENCE_DIRECTORY}/t002-generated-verification.json"
    if t002_status not in {"implemented", "verified"}:
        raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_T002_STATE_INVALID")
    if t002_status == "verified" and t002_path not in entries:
        raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_T002_CLOSURE_MISSING")

    evidence_directory = repo / CORE.EVIDENCE_DIRECTORY
    actual_generated = {
        f"{CORE.EVIDENCE_DIRECTORY}/{path.name}"
        for path in evidence_directory.iterdir()
        if "-generated-" in path.name
    }
    actual_records = {path for path in actual_generated if GENERATED_RECORD.fullmatch(Path(path).name)}
    if actual_records != set(entries):
        raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_RECORD_RECONCILIATION_FAILED")

    records: list[dict[str, object]] = []
    expected_files = set(entries)
    for path in sorted(entries):
        record = CORE.verify_generated_record(repo, repo / path)
        item = entries[path]
        if (
            record["implementation"]["commit"] != item["implementation_commit"]
            or record["evidence_tool"]["commit"] != item["evidence_tool_commit"]
        ):
            raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_GENERATED_COMMIT_MISMATCH")
        expected_files.add(record["github_ci"]["log"]["path"])
        expected_files.add(record["github_formal"]["log"]["path"])
        records.append(record)
    if actual_generated != expected_files:
        raise CORE.EvidenceGenerationError("EVIDENCE_LEDGER_GENERATED_FILE_STALE")
    return records


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--task-id")
    selection.add_argument("--all-present", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    repo = Path(__file__).resolve().parents[2]
    if arguments.task_id is not None:
        task = arguments.task_id.upper()
        if CORE.TASK_ID.fullmatch(task) is None:
            print("verify-task-evidence: FAIL: invalid task id", file=sys.stderr)
            return 1
        records = [
            repo
            / CORE.EVIDENCE_DIRECTORY
            / f"{task.lower()}-generated-verification.json"
        ]
    else:
        records = []
    try:
        if arguments.all_present:
            verified = reconcile_all(repo)
        else:
            verified = [CORE.verify_generated_record(repo, record) for record in records]
    except (CORE.EvidenceGenerationError, OSError, UnicodeDecodeError, ValueError) as error:
        print(f"verify-task-evidence: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"verify-task-evidence: OK: {len(verified)} generated record(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
