#!/usr/bin/env python3
"""Causal negative controls for the authored-claim and PID-boundary verifier."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "verify-claims.py"


def load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_claims", VERIFIER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load verify-claims.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PidBoundaryMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()
        cls.documents = cls.verifier.load_boundary_documents(ROOT)
        cls.runtime_sources = cls.verifier.load_runtime_sources(ROOT)

    def problems_after(self, name: str, old: str, new: str) -> list[str]:
        documents = dict(self.documents)
        self.assertIn(old, documents[name], f"negative-control anchor missing in {name}")
        documents[name] = documents[name].replace(old, new, 1)
        return self.verifier.boundary_contract_problems(**documents)

    def assert_problem(self, problems: list[str], expected: str) -> None:
        self.assertTrue(
            any(expected in problem for problem in problems),
            f"expected {expected!r}; received {problems!r}",
        )

    def test_current_boundary_artifacts_pass(self) -> None:
        self.assertEqual(
            [], self.verifier.boundary_contract_problems(**self.documents)
        )

    def test_current_runtime_source_absence_passes(self) -> None:
        self.assertEqual(
            [], self.verifier.runtime_pid_source_problems(self.runtime_sources)
        )

    def test_pid_dependency_breaks_current_source_absence(self) -> None:
        sources = dict(self.runtime_sources)
        anchor = "[workspace.dependencies]\n"
        self.assertIn(anchor, sources["Cargo.toml"])
        sources["Cargo.toml"] = sources["Cargo.toml"].replace(
            anchor, f'{anchor}pid-core = "0.9.0"\n', 1
        )
        problems = self.verifier.runtime_pid_source_problems(sources)
        self.assert_problem(problems, "current PID-absence claim")

    def test_authorize_equation_is_load_bearing(self) -> None:
        problems = self.problems_after(
            "contract",
            r"\operatorname{Authorize}(x,e)",
            r"\operatorname{Authorize}(x)",
        )
        self.assert_problem(problems, "authorization noninterference equation")

    def test_trusted_state_equation_is_load_bearing(self) -> None:
        problems = self.problems_after(
            "contract",
            r"\operatorname{TrustedStateSnapshot}(x,e)",
            r"\operatorname{TrustedStateSnapshot}(x)",
        )
        self.assert_problem(problems, "trusted-state noninterference equation")

    def test_audit_record_variation_is_load_bearing(self) -> None:
        problems = self.problems_after(
            "contract",
            r"\operatorname{AuditRecord}(x,e)",
            r"\operatorname{AuditRecord}(x)",
        )
        self.assert_problem(problems, "audit-record variation equation")

    def test_restrict_and_deny_are_not_implicit(self) -> None:
        problems = self.problems_after(
            "contract",
            "revoke, restrict, deny, or",
            "revoke, or",
        )
        self.assert_problem(problems, "complete authority verb boundary")

    def test_requested_outcomes_cannot_collapse(self) -> None:
        problems = self.problems_after(
            "contract",
            "Produced | Unavailable | ResourceRejected | Error",
            "Produced | Error",
        )
        self.assert_problem(problems, "closed requested outcomes")

    def test_audit_writer_requires_separate_authorization(self) -> None:
        problems = self.problems_after(
            "contract",
            "must be separately authorized for one bounded audit",
            "may use one bounded audit",
        )
        self.assert_problem(problems, "separately authorized record-only route")

    def test_data_minimization_clause_is_load_bearing(self) -> None:
        problems = self.problems_after(
            "contract", "omit raw sensor rows", "retain raw sensor rows"
        )
        self.assert_problem(problems, "confidentiality and minimization boundary")

    def test_sociotechnical_caveat_is_load_bearing(self) -> None:
        problems = self.problems_after(
            "contract",
            "software-path noninterference claims, not\nsociotechnical noninterference",
            "software-path noninterference claims, and\nsociotechnical noninterference",
        )
        self.assert_problem(problems, "sociotechnical limitation")

    def test_each_method_requires_its_own_svg_node(self) -> None:
        problems = self.problems_after(
            "svg", 'data-node="cusum"', 'data-node="nis"'
        )
        self.assert_problem(problems, "distinct node 'cusum'")

    def test_target_cannot_be_rewired_to_ksg(self) -> None:
        problems = self.problems_after(
            "svg",
            'data-edge="target->categorical-mgw" data-source="target" data-target="categorical-mgw"',
            'data-edge="target->ksg-mi" data-source="target" data-target="ksg-mi"',
        )
        self.assert_problem(problems, "target must join categorical MGW exactly once")

    def test_advisory_edge_into_authority_is_rejected(self) -> None:
        hostile = (
            '<path data-edge="audit-reference->authority-inputs" '
            'data-source="audit-reference" data-target="authority-inputs"/>\n</svg>'
        )
        problems = self.problems_after("svg", "</svg>", hostile)
        self.assert_problem(problems, "forbidden advisory/control edge")

    def test_method_edge_into_authority_is_rejected(self) -> None:
        hostile = (
            '<path data-edge="categorical-mgw->authority-inputs" '
            'data-source="categorical-mgw" data-target="authority-inputs"/>\n</svg>'
        )
        problems = self.problems_after("svg", "</svg>", hostile)
        self.assert_problem(problems, "forbidden advisory/control edge")

    def test_affirmative_pid_authority_prose_is_rejected(self) -> None:
        documents = dict(self.documents)
        documents["contract"] += "\nPID evidence can grant authority.\n"
        problems = self.verifier.boundary_contract_problems(**documents)
        self.assert_problem(
            problems, "contradictory affirmative PID/advisory authority prose"
        )

    def test_record_only_evidence_edge_is_required(self) -> None:
        problems = self.problems_after(
            "svg",
            'data-edge="typed-evidence->audit-reference" '
            'data-source="typed-evidence" data-target="audit-reference"',
            "",
        )
        self.assert_problem(problems, "required record-only evidence edge")

    def test_malformed_svg_fails_closed(self) -> None:
        problems = self.problems_after("svg", "</svg>", "")
        self.assert_problem(problems, "not well-formed XML")

    def test_historical_survey_requires_supersession_banner(self) -> None:
        problems = self.problems_after(
            "survey", "Superseded design survey", "Historical design survey"
        )
        self.assert_problem(problems, "lacks its superseded-history banner")

    def test_normative_spec_requires_record_only_phase(self) -> None:
        problems = self.problems_after(
            "specification",
            "Phase 16 — possible record-only Galadriel audit evidence",
            "Phase 16 — Galadriel evidence",
        )
        self.assert_problem(problems, "record-only phase")


if __name__ == "__main__":
    unittest.main()
