from __future__ import annotations

from contextlib import redirect_stdout
import json
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.prioritization import (
    prioritize_hypotheses,
    prioritize_hypotheses_file,
    write_prioritization_report,
)


class PrioritizationTests(unittest.TestCase):
    def setUp(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test-tmp"
        test_tmp.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_tmp)
        self.root = Path(self.temp.name)
        self.input_path = self.root / "hypotheses.json"
        self.hypothesis: dict[str, object] = {
            "category": "access_control",
            "summary": "Cross-account resource comparison needs review.",
            "evidence_for": [{"record_id": "a" * 24, "why": "Private resource marker matched."}],
            "evidence_against": [],
            "missing_controls": [],
            "confidence": "low",
            "next_check": {
                "kind": "http",
                "suggestion": "Review owner and actor controls.",
                "why": "A control is required.",
            },
            "status": "hypothesis",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, groups: list[dict[str, object]]) -> None:
        self.input_path.write_text(
            json.dumps({"type": "ai-hypotheses", "notice": "second opinion", "groups": groups}),
            encoding="utf-8",
        )

    def _group(self, hypothesis: dict[str, object], group_id: str = "a" * 24) -> dict[str, object]:
        return {"group_id": group_id, "status": "reviewed", "hypothesis": hypothesis}

    def test_keeps_priority_confidence_potential_impact_and_severity_separate(self) -> None:
        low = prioritize_hypotheses({}, [("a" * 24, self.hypothesis)], "sample", 100)["items"][0]
        high_confidence = dict(self.hypothesis, confidence="high")
        high = prioritize_hypotheses({}, [("a" * 24, high_confidence)], "sample", 100)["items"][0]

        self.assertEqual(low["priority_score"], high["priority_score"])
        self.assertEqual(low["hypothesis_confidence"]["value"], "low")
        self.assertEqual(low["potential_impact"]["band"], "high")
        self.assertEqual(low["demonstrated_severity"], "not_assessed")
        self.assertEqual(low["scope_status"], "not_verified")
        self.assertTrue(low["human_approval_required"])

    def test_evidence_and_controls_affect_priority_without_confirming(self) -> None:
        strong = dict(
            self.hypothesis,
            evidence_for=[
                {"record_id": f"{index:024x}", "why": "Observed in a separate record."} for index in range(3)
            ],
        )
        weak = dict(
            self.hypothesis,
            evidence_for=[],
            evidence_against=[{"record_id": "b" * 24, "why": "Control differed."}],
            missing_controls=["anonymous", "inverse", "negative control"],
        )
        result = prioritize_hypotheses({}, [("1" * 24, weak), ("2" * 24, strong)], "sample", 100)

        self.assertEqual(result["items"][0]["group_id"], "2" * 24)
        self.assertEqual(
            result["items"][0]["evidence_quality"]["repeatability"], "multiple_records_need_independence_review"
        )
        self.assertEqual(result["items"][0]["demonstrated_severity"], "not_assessed")

    def test_priority_order_prefers_offline_step_and_budget_defers_expensive_http(self) -> None:
        jwt = dict(self.hypothesis, category="jwt")
        redirect = dict(self.hypothesis, category="open_redirect")
        result = prioritize_hypotheses({}, [("1" * 24, redirect), ("2" * 24, jwt)], "sample", max_tests=1)

        self.assertEqual(result["items"][0]["category"], "jwt")
        self.assertEqual(result["plan"][0]["status"], "within_budget")
        self.assertEqual(result["plan"][0]["scope_status"], "not_applicable_to_offline_step")
        self.assertEqual(result["plan"][1]["status"], "deferred_over_budget")
        self.assertEqual(result["plan"][1]["approval_required"], True)
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertEqual(result["ollama_calls"], 0)

    def test_unknown_category_is_low_priority_and_not_a_finding(self) -> None:
        unknown = dict(
            self.hypothesis,
            category="unknown",
            evidence_for=[],
            missing_controls=["owner", "actor", "negative", "anonymous", "reproducibility", "scope"],
        )
        item = prioritize_hypotheses({}, [("c" * 24, unknown)], "sample", 100)["items"][0]
        self.assertEqual(item["skill"], "bugbounty-executor")
        self.assertEqual(item["research_priority"], "hold")
        self.assertEqual(item["potential_impact"]["band"], "unknown")
        self.assertEqual(item["demonstrated_severity"], "not_assessed")

    def test_empty_and_invalid_groups_are_reported_as_insufficient_input(self) -> None:
        result = prioritize_hypotheses({"groups": [{}, {}]}, [], "sample", 10)
        self.assertEqual(result["status"], "insufficient_input")
        self.assertEqual(result["unreviewed_groups"], 2)
        self.assertEqual(len(result["missing_inputs"]), 3)

    def test_file_loader_uses_validated_hypotheses_and_counts_unreviewed_groups(self) -> None:
        self._write([self._group(self.hypothesis), {"group_id": "b" * 24, "status": "unavailable"}])
        result = prioritize_hypotheses_file(self.input_path, "sample", 20)
        self.assertEqual(result["unreviewed_groups"], 1)
        self.assertEqual(result["status"], "review_required")

    def test_malformed_file_and_invalid_budget_fail_clearly(self) -> None:
        self.input_path.write_text("not-json", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "readable UTF-8 JSON"):
            prioritize_hypotheses_file(self.input_path, "sample", 10)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            prioritize_hypotheses({}, [], "sample", 0)
        with self.assertRaisesRegex(ValueError, "valid program"):
            prioritize_hypotheses({}, [], "", 10)

    def test_report_refuses_overwrite_until_force(self) -> None:
        path = self.root / "priority.json"
        result = prioritize_hypotheses({}, [("a" * 24, self.hypothesis)], "sample", 10)
        write_prioritization_report(result, path)
        with self.assertRaises(FileExistsError):
            write_prioritization_report(result, path)
        write_prioritization_report(dict(result, status="updated"), path, force=True)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["status"], "updated")

    def test_cli_dry_run_does_not_write_or_call_ollama(self) -> None:
        self._write([self._group(self.hypothesis)])
        output_path = self.root / "out.json"
        args = cli.build_parser().parse_args(
            [
                "ai",
                "prioritize",
                "sample",
                "--input",
                str(self.input_path),
                "--output",
                str(output_path),
                "--dry-run",
            ]
        )
        output = StringIO()
        with redirect_stdout(output):
            cli.cmd_ai_prioritize(args)
        self.assertFalse(output_path.exists())
        rendered = output.getvalue()
        self.assertIn("No target request, Ollama call or file write", rendered)
        self.assertIn('"demonstrated_severity": "not_assessed"', rendered)


if __name__ == "__main__":
    unittest.main()
