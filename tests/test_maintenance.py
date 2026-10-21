import json
import importlib.util
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
import sys
from types import SimpleNamespace
from unittest.mock import patch

from bugbounty_toolkit import __version__, cli
from bugbounty_toolkit.core.execution_budget import ExecutionBudget
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.core.reporting import render_markdown, render_pdf
from bugbounty_toolkit.diagnostics import diagnose
from bugbounty_toolkit.reporting.html_report import render_html_report
from bugbounty_toolkit.reporting.json_report import build_program_report, render_json_report
from bugbounty_toolkit.reporting.review_markdown import render_evidence_review


REPO_ROOT = Path(__file__).resolve().parents[1]


class MaintenanceTests(unittest.TestCase):
    def test_doctor_is_offline_and_reports_dependencies_skills_and_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skills = root / "skills"
            skills.mkdir()
            (skills / "bugbounty-executor").mkdir()
            (skills / "bugbounty-executor" / "SKILL.md").write_text(
                "---\nname: bugbounty-executor\n---\n", encoding="utf-8"
            )
            with patch("socket.create_connection", side_effect=AssertionError("diagnostics must remain offline")):
                result = diagnose(root / "records", skills_root=skills, installed_skills=root / "installed")
        self.assertEqual(result["toolkit_version"], __version__)
        self.assertEqual(result["network_requests_sent"], 0)
        names = {check["name"] for check in result["checks"]}
        self.assertIn("dependency:PyYAML", names)
        self.assertIn("tool:ollama", names)
        self.assertIn("skill-source", names)
        self.assertIn("skill-installation", names)
        self.assertIn("configuration", names)

    def test_doctor_cli_supports_json_without_creating_program_records(self):
        args = cli.build_parser().parse_args(["--records-root", "unused-records", "doctor", "--json"])
        output = StringIO()
        expected = {"toolkit_version": __version__, "network_requests_sent": 0, "ok": True, "checks": []}
        with patch.object(cli, "diagnose", return_value=expected) as run, redirect_stdout(output):
            args.func(args)
        run.assert_called_once()
        self.assertEqual(json.loads(output.getvalue()), expected)

    def test_evidence_review_markdown_is_readable_redacted_and_not_submitted(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.md"
            evidence = {
                "type": "access-control",
                "mode": "known-resource",
                "url": "https://example.test/item?access_token=private-query-token",
                "classification": "candidate",
                "confirmed": False,
                "requests_attempted": 3,
                "steps": [
                    {"step": "owner_control", "status_code": 200, "owner_private_match": True},
                    {"step": "actor_control", "status_code": 200, "actor_private_match": True},
                    {"step": "cross_read", "status_code": 200, "owner_private_match": True},
                ],
            }
            render_evidence_review(evidence, output)
            markdown = output.read_text(encoding="utf-8")
        self.assertIn("A/B Comparison Evidence", markdown)
        self.assertIn("owner_control", markdown)
        self.assertIn("cross_read", markdown)
        self.assertIn("Draft only", markdown)
        self.assertIn("Nothing is sent to a platform", markdown)
        self.assertNotIn("private-query-token", markdown)

    def test_version_flag_and_run_budget_flags_are_available(self):
        args = cli.build_parser().parse_args(
            [
                "request",
                "lab",
                "--url",
                "https://example.test",
                "--run-max-requests",
                "4",
                "--run-max-seconds",
                "30",
                "--run-max-concurrency",
                "2",
            ]
        )
        self.assertEqual(args.run_max_requests, 4)
        self.assertEqual(args.run_max_seconds, 30)
        self.assertEqual(args.run_max_concurrency, 2)
        self.assertEqual(__version__, "0.2.1")

    def test_run_summary_reports_aggregated_requests_without_sensitive_urls(self):
        budget = ExecutionBudget(max_requests=3, max_seconds=10, max_concurrency=2)
        lease = budget.acquire("https://example.test/api?access_token=do-not-print")
        lease.start()
        lease.finish(True)
        lease.release()
        args = SimpleNamespace(
            run_max_requests=3,
            run_max_seconds=10,
            run_max_concurrency=2,
            _execution_budget=budget,
        )
        output = StringIO()
        with redirect_stdout(output):
            cli.print_execution_summary(args)
        summary = output.getvalue()
        self.assertIn("1/3 requests sent", summary)
        self.assertIn("peak concurrency 1/2", summary)
        self.assertIn("destinations: example.test", summary)
        self.assertNotIn("do-not-print", summary)

    def test_doctor_reads_program_scope_authorization_and_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RecordStore(ProgramPaths(root / "records", "lab"))
            store.set_program_meta(authorization="local test policy")
            store.paths.scope_file.write_text(
                "https://example.test/api\n!https://example.test/api/private\n", encoding="utf-8"
            )
            result = diagnose(
                root / "records", program="lab", skills_root=REPO_ROOT / "skills", installed_skills=root / "installed"
            )
            store.close()
        checks = {item["name"]: item for item in result["checks"]}
        self.assertEqual(checks["program-scope"]["status"], "ok")
        self.assertEqual(checks["program-authorization"]["status"], "ok")
        self.assertEqual(checks["configuration"]["status"], "ok")

    def test_doctor_marks_malformed_program_settings_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RecordStore(ProgramPaths(root / "records", "lab"))
            store.paths.scope_file.write_text("*.bad*.example\n", encoding="utf-8")
            store.paths.program_dir.joinpath("settings.yaml").write_text("requests_per_second: 0\n", encoding="utf-8")
            result = diagnose(
                root / "records", program="lab", skills_root=REPO_ROOT / "skills", installed_skills=root / "installed"
            )
            store.close()
        checks = {item["name"]: item for item in result["checks"]}
        self.assertEqual(checks["program-scope"]["status"], "error")
        self.assertEqual(checks["configuration"]["status"], "error")
        self.assertFalse(result["ok"])

    def test_doctor_warns_for_uninitialized_program_and_missing_base_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = diagnose(
                root / "records",
                program="lab",
                skills_root=root / "missing-skills",
                installed_skills=root / "installed",
            )
        checks = {item["name"]: item for item in result["checks"]}
        self.assertEqual(checks["program-scope"]["status"], "warning")
        self.assertEqual(checks["program-authorization"]["status"], "warning")
        self.assertEqual(checks["skill-source"]["status"], "warning")

        original_find_spec = importlib.util.find_spec
        with patch(
            "bugbounty_toolkit.diagnostics.importlib.util.find_spec",
            side_effect=lambda name: None if name == "yaml" else original_find_spec(name),
        ):
            result = diagnose(
                Path(directory) / "records",
                skills_root=REPO_ROOT / "skills",
                installed_skills=Path(directory) / "installed",
            )
        checks = {item["name"]: item for item in result["checks"]}
        self.assertEqual(checks["dependency:PyYAML"]["status"], "error")
        self.assertIn("cannot validate YAML", checks["configuration"]["detail"])

    def test_program_json_html_markdown_and_pdf_reports_redact_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RecordStore(ProgramPaths(root / "records", "lab"))
            store.paths.scope_file.write_text("example.test\n", encoding="utf-8")
            evidence = store.paths.evidence_dir / "result.json"
            evidence.write_text(
                json.dumps({"token": "private-evidence-token", "note": "<script>unsafe</script>"}), encoding="utf-8"
            )
            store.add_run("request", "https://example.test/?access_token=private-url-token", ["request"], 0, evidence)
            store.add_finding(
                "F-1",
                "<script>finding</script>",
                "XSS",
                "medium",
                "https://example.test/?access_token=private-url-token",
                "Authorization: Bearer private-summary-token",
                str(evidence),
            )
            json_path = render_json_report(store, root / "program.json")
            html_path = render_html_report(store, root / "program.html")
            markdown_path = render_markdown(store.finding("F-1"), root / "finding.md")
            pdf_path = render_pdf(markdown_path, root / "finding.pdf")
            json_text = json_path.read_text(encoding="utf-8")
            html_text = html_path.read_text(encoding="utf-8")
            markdown_text = markdown_path.read_text(encoding="utf-8")
            self.assertIn("[redacted]", json_text)
            self.assertNotIn("private-evidence-token", json_text)
            self.assertNotIn("private-url-token", html_text)
            self.assertIn("&lt;script&gt;", html_text)
            self.assertNotIn("private-summary-token", markdown_text)
            self.assertIn("not submitted", markdown_text)
            self.assertTrue(pdf_path.is_file())
            store.close()

    def test_program_report_skips_external_files_and_marks_missing_or_invalid_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RecordStore(ProgramPaths(root / "records", "lab"))
            store.paths.scope_file.write_text("example.test\n", encoding="utf-8")
            invalid = store.paths.evidence_dir / "invalid.json"
            invalid.write_text("{not json", encoding="utf-8")
            outside = root / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            store.add_run("invalid", None, ["invalid"], 1, invalid)
            store.add_run("missing", None, ["missing"], 1, store.paths.evidence_dir / "missing.json")
            store.add_run("external", None, ["external"], 0, outside)
            report = build_program_report(store)
            self.assertEqual(len(report["evidence"]), 2)
            self.assertTrue(
                all(item.get("error") == "Evidence unavailable or invalid JSON" for item in report["evidence"])
            )
            store.close()

    def test_review_markdown_includes_probe_rows_without_ab_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "probe-review.md"
            render_evidence_review(
                {
                    "type": "cors",
                    "results": [{"origin": "https://evil.test", "status_code": 200, "classification": "VULNERABLE"}],
                },
                output,
            )
            markdown = output.read_text(encoding="utf-8")
        self.assertIn("No structured A/B step records", markdown)
        self.assertIn("https://evil.test", markdown)
        self.assertIn("VULNERABLE", markdown)
        with self.assertRaisesRegex(ValueError, "JSON object"):
            render_evidence_review([], Path("unused.md"))

    def test_report_command_builds_review_draft_in_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RecordStore(ProgramPaths(root / "records", "lab"))
            evidence = root / "evidence.json"
            evidence.write_text(
                json.dumps({"type": "access-control", "steps": [{"step": "cross_read", "status_code": 403}]}),
                encoding="utf-8",
            )
            args = cli.build_parser().parse_args(
                ["report", "lab", "--evidence-file", str(evidence), "--format", "markdown"]
            )
            output = StringIO()
            with patch.object(cli, "store_for", return_value=store), redirect_stdout(output):
                args.func(args)
            draft = store.paths.reports_dir / "evidence-review-evidence.md"
            self.assertTrue(draft.is_file())
            self.assertIn("cross_read", draft.read_text(encoding="utf-8"))
            self.assertIn("Nothing was submitted", output.getvalue())
            store.close()

    def test_main_reports_version_status_and_cli_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            output = StringIO()
            with (
                patch.object(sys, "argv", ["bbtk", "--records-root", directory, "status", "lab"]),
                redirect_stdout(output),
            ):
                cli.main()
            self.assertIn("Program: lab", output.getvalue())
            with patch.object(sys, "argv", ["bbtk", "--version"]), redirect_stdout(output):
                with self.assertRaises(SystemExit) as result:
                    cli.main()
            self.assertEqual(result.exception.code, 0)
            self.assertIn(__version__, output.getvalue())


if __name__ == "__main__":
    unittest.main()
