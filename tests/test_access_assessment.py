from __future__ import annotations

import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.access_assessment import assess_access_control


class AccessAssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test-tmp"
        test_tmp.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_tmp)
        self.root = Path(self.temp.name)
        self.case_path = self.root / "case.json"
        self.evidence_path = self.root / "access-check.json"
        self.case = {
            "accounts_authorized": True,
            "resource_private": True,
            "expected_cross_access": "deny",
            "checks": {
                "owner_resource": "order-A",
                "actor_resource": "order-B",
                "owner_marker": "private-marker-owner",
                "actor_marker": "private-marker-actor",
            },
        }
        self._write_case()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_case(self, case: dict[str, object] | None = None) -> None:
        self.case_path.write_text(json.dumps(case or self.case), encoding="utf-8")

    def _write_evidence(self, cross: dict[str, object] | None = None) -> None:
        steps: list[dict[str, object]] = [
            {
                "step": "owner_control",
                "application_success": True,
                "resource_match": True,
                "private_match": True,
                "status_code": 200,
            },
            {
                "step": "actor_control",
                "application_success": True,
                "resource_match": True,
                "private_match": True,
                "status_code": 200,
            },
        ]
        if cross is not None:
            steps.append({"step": "cross_read", **cross})
        self.evidence_path.write_text(
            json.dumps({"type": "access-control", "mode": "read", "controls_valid": True, "steps": steps}),
            encoding="utf-8",
        )

    def test_private_marker_and_resource_match_are_only_a_possible_finding(self) -> None:
        self._write_evidence(
            {
                "application_success": True,
                "owner_resource_match": True,
                "owner_private_match": True,
                "status_code": 403,
            }
        )
        result = assess_access_control(self.case_path, self.evidence_path)
        self.assertEqual(result["classification"], "possible_unauthorized_access")
        self.assertEqual(result["controls_classification"], "legitimate_access")
        self.assertFalse(result["confirmed"])
        self.assertFalse(result["status_code_used"])
        self.assertFalse(result["model_opinion_used"])

    def test_application_denial_is_not_inferred_from_http_status(self) -> None:
        self._write_evidence(
            {
                "application_success": False,
                "owner_resource_match": False,
                "owner_private_match": False,
                "status_code": 200,
            }
        )
        self.assertEqual(assess_access_control(self.case_path, self.evidence_path)["classification"], "denied")

    def test_missing_ownership_predicates_returns_insufficient(self) -> None:
        self._write_evidence({"application_success": True, "owner_resource_match": False, "status_code": 200})
        result = assess_access_control(self.case_path, self.evidence_path)
        self.assertEqual(result["classification"], "insufficient_evidence")
        self.assertFalse(result["confirmed"])

    def test_own_controls_are_labeled_legitimate_but_missing_cross_is_inconclusive(self) -> None:
        self._write_evidence()
        result = assess_access_control(self.case_path, self.evidence_path)
        self.assertEqual(result["classification"], "insufficient_evidence")
        self.assertEqual(result["controls_classification"], "legitimate_access")

    def test_case_missing_private_marker_attestation_returns_insufficient(self) -> None:
        bad_case = dict(self.case)
        bad_case["checks"] = {"owner_resource": "order-A", "actor_resource": "order-B"}
        self._write_case(bad_case)
        self._write_evidence({"application_success": True, "owner_resource_match": True, "owner_private_match": True})
        self.assertEqual(
            assess_access_control(self.case_path, self.evidence_path)["classification"], "insufficient_evidence"
        )

    def test_unified_fingerprints_alone_cannot_map_ownership(self) -> None:
        result = assess_access_control(self.case_path, None)
        self.assertEqual(result["classification"], "insufficient_evidence")
        self.assertIn("do not map ownership", result["reason"])

    def test_hypotheses_command_adds_deterministic_assessment(self) -> None:
        bundle_path = self.root / "bundle.json"
        bundle_path.write_text(
            json.dumps({"type": "unified-evidence-bundle", "bundle_id": "d" * 24, "records": []}),
            encoding="utf-8",
        )
        self._write_evidence(
            {
                "application_success": True,
                "owner_resource_match": True,
                "owner_private_match": True,
            }
        )
        old_root = cli.RECORDS_ROOT
        cli.RECORDS_ROOT = self.root / "records"
        try:
            args = cli.build_parser().parse_args(
                [
                    "ai",
                    "hypotheses",
                    "lab",
                    "--input",
                    str(bundle_path),
                    "--case-file",
                    str(self.case_path),
                    "--access-evidence",
                    str(self.evidence_path),
                    "--dry-run",
                ]
            )
            output = StringIO()
            with (
                patch("bugbounty_toolkit.cli.analyze_hypotheses", return_value={"groups": []}),
                redirect_stdout(output),
            ):
                cli.cmd_ai_hypotheses(args)
            rendered = output.getvalue()
            result = json.loads(rendered[rendered.index("{\n") :])
            self.assertEqual(result["access_control_assessment"]["classification"], "possible_unauthorized_access")
            self.assertFalse((self.root / "records").exists())
        finally:
            cli.RECORDS_ROOT = old_root


if __name__ == "__main__":
    unittest.main()
