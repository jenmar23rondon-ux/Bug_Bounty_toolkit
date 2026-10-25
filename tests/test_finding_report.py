from __future__ import annotations

from contextlib import redirect_stdout
import json
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.reporting.finding_report import (
    PENDING,
    build_evidence_finding_report,
    render_evidence_report_html,
    render_evidence_report_json,
    render_evidence_report_markdown,
    render_evidence_report_pdf,
)


class FindingReportTests(unittest.TestCase):
    def test_candidate_report_has_complete_schema_and_explicit_missing_fields(self) -> None:
        report = build_evidence_finding_report(
            {
                "type": "access-control",
                "classification": "possible_unauthorized_access",
                "confirmed": True,
                "status_code": 200,
                "ai_review": {"decision": "candidate", "reason": "model opinion"},
                "url": "https://example.test/api/orders?access_token=secret",
                "method": "GET",
                "steps": [
                    {"step": "owner_control", "application_success": True, "status_code": 200},
                    {"step": "public_negative_control", "application_success": False, "status_code": 403},
                ],
            },
            program="demo",
            source_name="burp-evidence.json",
        )

        self.assertEqual(report["validation_state"], "candidate")
        self.assertFalse(report["severity_assessed_by_toolkit"])
        self.assertFalse(report["submitted"])
        self.assertEqual(report["category"], "access-control")
        self.assertEqual(report["cwe"], "CWE-639")
        self.assertEqual(report["method"], "GET")
        self.assertEqual(report["expected_result"], PENDING)
        self.assertEqual(report["reproduction_steps"], [PENDING])
        self.assertIn("public_negative_control", report["negative_controls"])
        self.assertEqual(report["evidence_sources"], ["burp-evidence.json"])
        self.assertNotIn("secret", json.dumps(report))
        self.assertNotEqual(report["finding_id"], PENDING)

    def test_only_browser_observed_harmless_xss_execution_is_validated(self) -> None:
        validated = build_evidence_finding_report(
            {
                "type": "xss",
                "results": [
                    {
                        "classification": "confirmed",
                        "confirmed": True,
                        "browser_execution_observed": True,
                        "execution": {"classification": "confirmed", "marker_observed": True},
                    }
                ],
            }
        )
        claimed = build_evidence_finding_report(
            {"type": "xss", "classification": "confirmed", "confirmed": True, "status_code": 200}
        )
        self.assertEqual(validated["validation_state"], "validated")
        self.assertEqual(claimed["validation_state"], "inconclusive")
        self.assertNotIn("validated", json.dumps(claimed["validation_basis"]))

    def test_unobserved_and_inconclusive_states_are_distinct(self) -> None:
        unobserved = build_evidence_finding_report(
            {"type": "sqli", "results": [{"classification": "not_reproducible"}]}
        )
        inconclusive = build_evidence_finding_report({"type": "sqli", "results": [{"classification": "error"}]})
        http_only = build_evidence_finding_report({"type": "access-control", "steps": [{"status_code": 200}]})
        self.assertEqual(unobserved["validation_state"], "not_observed")
        self.assertEqual(inconclusive["validation_state"], "inconclusive")
        self.assertEqual(http_only["validation_state"], "inconclusive")

    def test_evidence_for_against_and_reproduction_are_redacted_and_preserved(self) -> None:
        report = build_evidence_finding_report(
            {
                "type": "xss",
                "evidence_for": [{"record_id": "ev-1", "why": "Marker reflected; token=private"}],
                "evidence_against": [{"record_id": "ev-2", "why": "Browser did not execute the marker."}],
                "negative_controls": ["known-safe endpoint"],
                "preconditions": ["Two researcher-controlled accounts"],
                "steps_to_reproduce": ["Use the supplied local capture"],
                "impact": "Information disclosure not established.",
                "severity": "medium",
                "severity_rationale": "Pending manual review.",
                "limitations": ["Single test run"],
            }
        )
        self.assertEqual(report["evidence_for"][0]["record_id"], "ev-1")
        self.assertNotIn("private", report["evidence_for"][0]["why"])
        self.assertEqual(report["evidence_against"][0]["record_id"], "ev-2")
        self.assertEqual(report["preconditions"], ["Two researcher-controlled accounts"])
        self.assertEqual(report["reproduction_steps"], ["Use the supplied local capture"])
        self.assertEqual(report["severity_suggested"], "medium")
        self.assertIn("Single test run", report["limitations"])

    def test_markdown_report_escapes_untrusted_links_and_html(self) -> None:
        report = build_evidence_finding_report(
            {"type": "xss", "title": "[click](javascript:alert(1))", "summary": "&lt;script&gt;"}
        )
        markdown = render_evidence_report_markdown(report)
        self.assertNotIn("[click](javascript:", markdown)
        self.assertIn("\\[click\\]\\(javascript:", markdown)
        self.assertIn("&amp;lt;script&amp;gt;", markdown)

    def test_markdown_html_json_and_pdf_render_same_redacted_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = build_evidence_finding_report(
                {
                    "type": "xss",
                    "title": "<script>alert(1)</script>",
                    "summary": "candidate only",
                    "url": "https://example.test/path?token=private-token",
                    "results": [{"classification": "possible", "method": "GET", "status_code": 200}],
                },
                program="demo",
            )
            markdown = render_evidence_report_markdown(report)
            html_path = render_evidence_report_html(report, root / "report.html")
            json_path = render_evidence_report_json(report, root / "report.json")
            pdf_path = render_evidence_report_pdf(report, root / "report.pdf")
            html_text = html_path.read_text(encoding="utf-8")
            json_text = json_path.read_text(encoding="utf-8")
            pdf_bytes = pdf_path.read_bytes()

        self.assertIn(PENDING, markdown)
        self.assertIn("Evidence supporting the hypothesis", markdown)
        self.assertIn("Remediation recommendation", markdown)
        self.assertNotIn("<script>alert(1)</script>", html_text)
        self.assertNotIn("private-token", html_text)
        self.assertIn("evidence-finding-report", json_text)
        self.assertNotIn("private-token", json_text)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_report_cli_supports_formats_and_requires_force_to_replace_evidence_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps({"type": "sqli", "classification": "possible"}), encoding="utf-8")
            store = RecordStore(ProgramPaths(root / "records", "demo"))
            try:
                with patch.object(cli, "store_for", return_value=store):
                    for format_name in ("json", "html", "pdf"):
                        args = cli.build_parser().parse_args(
                            ["report", "demo", "--evidence-file", str(evidence), "--format", format_name]
                        )
                        with redirect_stdout(StringIO()):
                            cli.cmd_report(args)
                        self.assertTrue((store.paths.reports_dir / f"evidence-review-evidence.{format_name}").is_file())

                    md_args = cli.build_parser().parse_args(["report", "demo", "--evidence-file", str(evidence)])
                    with redirect_stdout(StringIO()):
                        cli.cmd_report(md_args)
                    with self.assertRaisesRegex(ValueError, "Use --force"):
                        cli.cmd_report(md_args)
                    md_args.force = True
                    with redirect_stdout(StringIO()):
                        cli.cmd_report(md_args)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
