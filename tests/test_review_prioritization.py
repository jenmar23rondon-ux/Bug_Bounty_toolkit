from __future__ import annotations

from contextlib import redirect_stdout
import copy
import json
from io import StringIO
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.prioritization import _score
from bugbounty_toolkit.analysis.review_prioritization import ABSTAIN_REASONS, prioritize_review


def _evidence(host: str, endpoint: str, confidence: str | None, response: bool) -> dict[str, object]:
    return {
        "url": f"http://{host}{endpoint}",
        "host": host,
        "endpoint": endpoint,
        "method": "GET",
        "status_code": 200 if response else None,
        "response_present": response,
        "ingestion_confidence": confidence,
        "ingestion_diagnostics": [],
    }


def _finding(
    review_id: str,
    *,
    severity: str | None,
    confidence: str | None = "observed",
    response: bool = True,
    vulnerability_class: str = "cross_site_scripting",
    access_confirmed: bool = False,
    vulnerabilities_confirmed: int = 0,
) -> dict[str, object]:
    return {
        "review_id": review_id,
        "schema": "bbtk.external-finding/1",
        "origin": {"tool": "nuclei", "source_file": f"{review_id}.json", "record_index": 1},
        "evidence": _evidence("127.0.0.1", f"/{review_id}", confidence, response),
        "hypothesis": {
            "vulnerability_class": vulnerability_class,
            "vulnerability_claimed": True,
            "severity_claimed": severity,
        },
        "status": "candidate" if response else "needs_review",
        "access_confirmed": access_confirmed,
        "vulnerabilities_confirmed": vulnerabilities_confirmed,
    }


class ReviewPrioritizationTests(unittest.TestCase):
    def test_tool_severity_cannot_place_an_item_first_or_confirm_it(self) -> None:
        bare = _finding("bare-critical", severity="critical", confidence=None, response=False)
        observed = _finding("observed-info", severity="info")
        original = copy.deepcopy([bare, observed])
        result = prioritize_review("review-lab", ["127.0.0.1"], 10, external=[bare, observed], dry_run=True)

        self.assertEqual([row["item_id"] for row in result["ranked"]], ["observed-info"])
        self.assertEqual(result["abstained"][0]["item_id"], "bare-critical")
        self.assertEqual(result["abstained"][0]["reason"], "severity_without_supporting_evidence")
        self.assertEqual(result["access_confirmed"], False)
        self.assertEqual(result["vulnerabilities_confirmed"], 0)
        self.assertEqual(result["confirmations_created"], 0)
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertTrue(result["human_approval_required"])
        for row in [*result["ranked"], *result["abstained"]]:
            self.assertFalse(row["access_confirmed"])
            self.assertEqual(row["vulnerabilities_confirmed"], 0)
            self.assertFalse(row["finding_confirmed"])
            self.assertFalse(row["severity_used_in_score"])
            self.assertTrue(row["human_approval_required"])
            self.assertEqual(row["demonstrated_severity"], "not_assessed")
        self.assertEqual([bare, observed], original)

    def test_equal_evidence_ignores_severity_and_reuses_the_existing_score(self) -> None:
        critical = _finding("b-critical", severity="critical")
        info = _finding("a-info", severity="info")
        critical["access_confirmed"] = True
        critical["vulnerabilities_confirmed"] = 4
        result = prioritize_review("review-lab", ["127.0.0.1"], 10, external=[critical, info], dry_run=True)
        rows = {row["item_id"]: row for row in result["ranked"]}

        self.assertEqual([row["item_id"] for row in result["ranked"]], ["a-info", "b-critical"])
        self.assertEqual(rows["a-info"]["priority_score"], rows["b-critical"]["priority_score"])
        self.assertEqual(rows["b-critical"]["score_components"]["severity_points"], 0)
        self.assertFalse(rows["b-critical"]["access_confirmed"])
        self.assertEqual(rows["b-critical"]["vulnerabilities_confirmed"], 0)
        self.assertGreaterEqual(result["confirmation_claims_ignored"], 1)
        expected = _score(
            {"evidence_for": [{}], "evidence_against": [], "missing_controls": []},
            "medium",
            0,
            0,
        )
        self.assertEqual(rows["a-info"]["priority_score"], expected - 10)

    def test_missing_scope_abstains_instead_of_ranking(self) -> None:
        result = prioritize_review("review-lab", [], 10, external=[_finding("only", severity="critical")], dry_run=True)
        self.assertEqual(result["ranked"], [])
        self.assertEqual(result["abstained"][0]["reason"], "missing_scope")
        self.assertIn(result["abstained"][0]["reason"], ABSTAIN_REASONS)

    def test_budget_defers_without_sending_or_confirming(self) -> None:
        def fail_socket(*_args: object, **_kwargs: object) -> socket.socket:
            raise AssertionError("review prioritization attempted a network connection")

        with patch("socket.socket", fail_socket):
            result = prioritize_review(
                "review-lab",
                ["127.0.0.1"],
                1,
                external=[_finding("needs-http", severity="low", vulnerability_class="open_redirect")],
                requests_per_second=1,
                dry_run=True,
            )
        self.assertEqual(result["ranked"][0]["budget_status"], "deferred_over_budget")
        self.assertEqual(result["ranked"][0]["execution_status"], "not_started_requires_human_approval")
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertEqual(result["rate_limit"]["requests_sent"], 0)
        self.assertEqual(result["rate_limit"]["requests_per_second"], 1.0)
        self.assertFalse(result["scope_validated"])

    def test_repeat_is_deterministic_and_explanations_name_every_factor(self) -> None:
        finding = _finding("steady", severity="low")
        first = prioritize_review("review-lab", ["127.0.0.1"], 10, external=[finding], dry_run=True)
        second = prioritize_review("review-lab", ["127.0.0.1"], 10, external=[finding], dry_run=True)
        self.assertEqual(first, second)
        explanation = first["ranked"][0]["explanation"]
        for phrase in (
            "Origin:",
            "Location:",
            "Evidence strength:",
            "Session/actor:",
            "Corroboration:",
            "Vulnerability class:",
            "Contradictions:",
        ):
            self.assertIn(phrase, explanation)
        self.assertIn("does not confirm", explanation)

    def test_cli_dry_run_prints_order_without_writing(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test-tmp"
        test_tmp.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_tmp) as directory:
            root = Path(directory)
            scope = root / "scope.txt"
            scope.write_text("127.0.0.1\n", encoding="utf-8")
            external = root / "external.json"
            external.write_text(json.dumps([_finding("cli-info", severity="info")]), encoding="utf-8")
            output = root / "out.json"
            args = cli.build_parser().parse_args(
                [
                    "evidence",
                    "prioritize",
                    "review-lab",
                    "--scope-file",
                    str(scope),
                    "--external",
                    str(external),
                    "--max-tests",
                    "10",
                    "--requests-per-second",
                    "1",
                    "--output",
                    str(output),
                    "--attest-local-review",
                    "--dry-run",
                ]
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                cli.cmd_evidence_prioritize(args)
            rendered = stdout.getvalue()
            self.assertFalse(output.exists())
            self.assertIn("[dry-run] No target request or file write performed.", rendered)
            self.assertIn('"access_confirmed": false', rendered)
            self.assertIn('"vulnerabilities_confirmed": 0', rendered)
            self.assertIn("cli-info", rendered)


if __name__ == "__main__":
    unittest.main()
