from __future__ import annotations

import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.access_assessment import assess_access_control, assess_access_control_data


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

    def test_account_matrix_reports_possible_bola_from_predicates_not_status(self) -> None:
        case = {
            **self.case,
            "additional_accounts": {"third": {"resource": "order-C", "marker": "private-marker-third"}},
        }
        names = ("owner", "actor", "third")
        steps: list[dict[str, object]] = [
            {
                "step": f"{name}_control",
                "application_success": True,
                "resource_match": True,
                "private_match": True,
            }
            for name in names
        ]
        matrix: list[dict[str, object]] = []
        for source in names:
            for target in names:
                if source == target:
                    continue
                candidate = source == "actor" and target == "owner"
                steps.append(
                    {
                        "step": f"cross_{source}_to_{target}",
                        "application_success": candidate,
                        "resource_match": candidate,
                        "private_match": candidate,
                        "status_code": 403 if candidate else 200,
                    }
                )
                matrix.append(
                    {
                        "session_account": source,
                        "resource_owner": target,
                        "access_type": "cross",
                        "confirmed": False,
                    }
                )
        evidence = {
            "type": "access-control",
            "mode": "account-matrix",
            "controls_valid": True,
            "matrix_accounts": list(names),
            "matrix": matrix,
            "steps": steps,
        }
        result = assess_access_control_data(case, evidence)
        self.assertEqual(result["category"], "BOLA")
        self.assertEqual(result["classification"], "possible_unauthorized_access")
        self.assertFalse(result["confirmed"])
        self.assertFalse(result["status_code_used"])
        self.assertNotIn("assessment_classification", matrix[0])

    def test_incomplete_account_matrix_is_not_called_denied(self) -> None:
        case = {
            **self.case,
            "additional_accounts": {"third": {"resource": "order-C", "marker": "private-marker-third"}},
        }
        evidence = {
            "type": "access-control",
            "mode": "account-matrix",
            "controls_valid": True,
            "matrix_accounts": ["owner", "actor", "third"],
            "steps": [
                {
                    "step": f"{name}_control",
                    "application_success": True,
                    "resource_match": True,
                    "private_match": True,
                }
                for name in ("owner", "actor", "third")
            ],
            "matrix": [],
        }
        result = assess_access_control_data(case, evidence)
        self.assertEqual(result["classification"], "insufficient_evidence")
        self.assertFalse(result["confirmed"])

    def test_function_matrix_uses_allowed_controls_and_body_predicates_not_status(self) -> None:
        case = {
            "type": "function-access-case",
            "accounts_authorized": True,
            "accounts": {"admin": "admin", "reader": "reader"},
            "functions": [
                {
                    "name": "export",
                    "allowed_roles": ["admin"],
                    "restricted": True,
                    "read_only_attested": True,
                    "requests": {"admin": "admin.txt", "reader": "reader.txt"},
                }
            ],
        }
        evidence = {
            "type": "access-control",
            "mode": "function-matrix",
            "functions": [
                {
                    "function": "export",
                    "required_roles": ["admin"],
                    "read_only_attested": True,
                    "controls_valid": True,
                    "results": [
                        {
                            "account": "admin",
                            "role": "admin",
                            "expected_access": "allow",
                            "success_match": True,
                            "marker_match": True,
                            "marker_seen": True,
                            "confirmed": False,
                            "status_code": 200,
                        },
                        {
                            "account": "reader",
                            "role": "reader",
                            "expected_access": "deny",
                            "success_match": True,
                            "denial_match": False,
                            "marker_match": True,
                            "marker_seen": True,
                            "confirmed": False,
                            "status_code": 403,
                        },
                    ],
                }
            ],
        }
        result = assess_access_control_data(case, evidence)
        self.assertEqual(result["category"], "BFLA")
        self.assertEqual(result["classification"], "possible_bfla")
        self.assertFalse(result["confirmed"])
        self.assertFalse(result["status_code_used"])

    def test_function_matrix_http_200_without_application_proof_is_not_a_candidate(self) -> None:
        case = {
            "type": "function-access-case",
            "accounts_authorized": True,
            "accounts": {"admin": "admin", "reader": "reader"},
            "functions": [
                {
                    "name": "export",
                    "allowed_roles": ["admin"],
                    "restricted": True,
                    "read_only_attested": True,
                    "requests": {"admin": "admin.txt", "reader": "reader.txt"},
                }
            ],
        }
        evidence = {
            "type": "access-control",
            "mode": "function-matrix",
            "functions": [
                {
                    "function": "export",
                    "required_roles": ["admin"],
                    "read_only_attested": True,
                    "controls_valid": True,
                    "results": [
                        {
                            "account": "admin",
                            "role": "admin",
                            "expected_access": "allow",
                            "success_match": True,
                            "marker_match": True,
                            "marker_seen": True,
                            "confirmed": False,
                        },
                        {
                            "account": "reader",
                            "role": "reader",
                            "expected_access": "deny",
                            "success_match": False,
                            "denial_match": True,
                            "marker_match": False,
                            "marker_seen": False,
                            "confirmed": False,
                            "status_code": 200,
                        },
                    ],
                }
            ],
        }
        result = assess_access_control_data(case, evidence)
        self.assertEqual(result["classification"], "denied")
        self.assertFalse(result["status_code_used"])

    def test_function_matrix_invalid_positive_control_prevents_candidate(self) -> None:
        case = {
            "type": "function-access-case",
            "accounts_authorized": True,
            "accounts": {"admin": "admin", "reader": "reader"},
            "functions": [
                {
                    "name": "export",
                    "allowed_roles": ["admin"],
                    "restricted": True,
                    "read_only_attested": True,
                    "requests": {"admin": "admin.txt", "reader": "reader.txt"},
                }
            ],
        }
        evidence = {
            "type": "access-control",
            "mode": "function-matrix",
            "functions": [
                {
                    "function": "export",
                    "required_roles": ["admin"],
                    "read_only_attested": True,
                    "controls_valid": False,
                    "results": [
                        {
                            "account": "admin",
                            "role": "admin",
                            "expected_access": "allow",
                            "success_match": False,
                            "marker_match": False,
                            "marker_seen": False,
                            "confirmed": False,
                        },
                        {
                            "account": "reader",
                            "role": "reader",
                            "expected_access": "deny",
                            "success_match": True,
                            "marker_match": True,
                            "marker_seen": True,
                            "confirmed": False,
                        },
                    ],
                }
            ],
        }
        self.assertEqual(
            assess_access_control_data(case, evidence)["classification"],
            "insufficient_evidence",
        )


if __name__ == "__main__":
    unittest.main()
