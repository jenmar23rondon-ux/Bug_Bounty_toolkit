import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from bugbounty_toolkit.core.settings import load_settings
from bugbounty_toolkit.core.records import ProgramPaths


class WorkflowLab(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append(self.path)
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/cors":
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            return
        if parsed.path == "/redirect-test":
            destination = query.get("next", [""])[0]
            self.send_response(302)
            self.send_header("Location", destination if "evil.com" in destination else "/dashboard")
            self.end_headers()
            return
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/excluded")
            self.end_headers()
            return
        body = "no reflection"
        if parsed.path == "/search":
            body = "<html><body>" + " ".join(value for values in query.values() for value in values) + "</body></html>"
        if parsed.path == "/encoded":
            body = "<html>" + html.escape(" ".join(value for values in query.values() for value in values)) + "</html>"
        if parsed.path == "/sql" and any("'" in value or '"' in value for values in query.values() for value in values):
            body = "You have an error in your SQL syntax"
        self.send_response(404 if parsed.path == "/missing" else 200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), WorkflowLab)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.worker.join()
        cls.server.server_close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.records = self.root / "records"
        config = self.root / "settings.yaml"
        config.write_text("requests_per_second: 20\nmax_concurrency: 2\nmax_tests: 8\n")
        self.cli(
            "init",
            "lab",
            "--authorization",
            "local laboratory owned for tests",
            "--automation-allowed",
            "--config",
            str(config),
        )
        self.cli("scope", "add", "lab", self.base)
        self.cli("scope", "add", "lab", self.base + "/excluded", "--exclude")
        WorkflowLab.hits.clear()

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, *args, expected=0):
        command = [sys.executable, "-m", "bugbounty_toolkit.cli", "--records-root", str(self.records), *args]
        process = subprocess.run(command, capture_output=True, text=True, timeout=30, env=os.environ.copy())
        self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
        return process

    def test_request_xss_and_reports_end_to_end(self):
        self.cli("request", "lab", "--url", self.base + "/quiet", "--param", "page=2")
        routes = self.root / "routes.txt"
        routes.write_text("/search\n/quiet\n")
        parameters = self.root / "parameters.txt"
        parameters.write_text("q\n")
        self.cli(
            "xss", "lab", "--routes", str(routes), "--parameters", str(parameters), "--base-url", self.base, "--dry-run"
        )
        self.assertEqual(len(WorkflowLab.hits), 1)
        self.cli("xss", "lab", "--routes", str(routes), "--parameters", str(parameters), "--base-url", self.base)
        self.cli("report", "lab", "--format", "json")
        self.cli("report", "lab", "--format", "html")
        path = self.records / "lab" / "reports"
        report = json.loads((path / "program-report.json").read_text())
        self.assertEqual(report["counts"]["runs"], 2)
        xss = next(item["data"] for item in report["evidence"] if item["data"].get("type") == "xss")
        self.assertEqual(len(xss["results"]), 8)
        self.assertEqual(sum(item["classification"] == "possible" for item in xss["results"]), 4)
        self.assertFalse(any(item["confirmed"] for item in xss["results"]))
        document = (path / "program-report.html").read_text()
        self.assertIn("&lt;bbtkxss", document)
        self.assertNotIn("<bbtkxss", document)

    def test_shared_request_budget_stops_native_batch_and_prints_partial_summary(self):
        routes = self.root / "budget-routes.txt"
        routes.write_text(self.base + "/quiet\n")
        parameters = self.root / "budget-parameters.txt"
        parameters.write_text("q\n")
        result = self.cli(
            "xss",
            "lab",
            "--routes",
            str(routes),
            "--parameters",
            str(parameters),
            "--run-max-requests",
            "2",
            "--run-max-seconds",
            "10",
            "--run-max-concurrency",
            "1",
        )
        self.assertEqual(len(WorkflowLab.hits), 2)
        self.assertIn("2/2 requests sent", result.stdout)
        self.assertIn("destinations: 127.0.0.1", result.stdout)
        evidence = next((self.records / "lab" / "evidence" / "xss").glob("*.json"))
        data = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(data["stop_reason"], "transport_error")
        self.assertEqual(len(data["results"]), 3)

    def test_scope_and_rate_fail_before_network(self):
        self.cli("request", "lab", "--url", self.base + "/search", "--dry-run")
        self.cli("request", "lab", "--url", self.base + "/excluded", expected=1)
        self.cli("request", "lab", "--url", self.base + "/search", "--rate", "21", expected=1)
        self.assertEqual(WorkflowLab.hits, [])

    def test_sqli_dry_run_local_requests_and_report(self):
        routes = self.root / "sql-routes.txt"
        routes.write_text(self.base + "/sql?q=original\n")
        params = self.root / "params.txt"
        params.write_text("q\n")
        self.cli("sqli", "lab", "--routes", str(routes), "--parameters", str(params), "--max-tests", "3", "--dry-run")
        self.assertEqual(WorkflowLab.hits, [])
        self.cli("sqli", "lab", "--routes", str(routes), "--parameters", str(params), "--max-tests", "3")
        self.assertEqual(len(WorkflowLab.hits), 3)
        self.cli("report", "lab", "--format", "json")
        report = json.loads((self.records / "lab" / "reports" / "program-report.json").read_text())
        probes = next(item["data"] for item in report["evidence"] if item["data"].get("type") == "sqli")
        self.assertEqual([item["classification"] for item in probes["results"]], ["baseline", "possible", "possible"])
        self.assertFalse(any(item["confirmed"] for item in probes["results"]))

    def test_cors_and_open_redirect_cli_dry_run_and_local_execution(self):
        self.cli("cors-check", "lab", "--url", self.base + "/cors", "--dry-run")
        self.cli(
            "open-redirect", "lab", "--url", self.base + "/redirect-test?next=%2Fhome", "--param", "next", "--dry-run"
        )
        self.assertEqual(WorkflowLab.hits, [])

        cors = self.cli("cors-check", "lab", "--url", self.base + "/cors")
        self.assertIn("4 header-vulnerable", cors.stdout)
        self.assertIn("confirmed=0 candidate=4", cors.stdout)
        self.assertEqual(len(WorkflowLab.hits), 4)
        WorkflowLab.hits.clear()

        redirect = self.cli(
            "open-redirect", "lab", "--url", self.base + "/redirect-test?next=%2Fhome", "--param", "next"
        )
        self.assertIn("vulnerable of 5 probes", redirect.stdout)
        self.assertEqual(len(WorkflowLab.hits), 5)
        self.assertTrue(all(path.startswith("/redirect-test?") for path in WorkflowLab.hits))

    def test_external_plan_is_private_and_never_reaches_server(self):
        url = self.base + "/search?q=1&access_token=private-lab-token"
        self.cli("tool-plan", "lab", "--tool", "sqlmap", "--url", url, "--parameter", "q", "--dry-run")
        self.assertFalse(list((self.records / "lab" / "raw").glob("external-plans/*.json")))
        self.cli("tool-plan", "lab", "--tool", "sqlmap", "--url", url, "--parameter", "q")
        self.assertEqual(WorkflowLab.hits, [])
        private_plans = list((self.records / "lab" / "raw").glob("external-plans/*.json"))
        self.assertEqual(len(private_plans), 1)
        self.assertIn("private-lab-token", private_plans[0].read_text())
        self.cli("report", "lab", "--format", "json")
        report = (self.records / "lab" / "reports" / "program-report.json").read_text()
        self.assertNotIn("private-lab-token", report)

    def test_evidence_markdown_draft_redacts_tokens_and_never_submits(self):
        evidence = self.records / "lab" / "evidence" / "access-control" / "review.json"
        evidence.parent.mkdir(parents=True)
        evidence.write_text(
            json.dumps(
                {
                    "type": "access-control",
                    "mode": "known-resource",
                    "url": "https://example.test/item?access_token=private-lab-token",
                    "classification": "candidate",
                    "confirmed": False,
                    "requests_attempted": 3,
                    "steps": [
                        {"step": "owner_control", "status_code": 200, "owner_private_match": True},
                        {"step": "actor_control", "status_code": 200, "actor_private_match": True},
                        {"step": "cross_read", "status_code": 200, "owner_private_match": True},
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = self.cli("report", "lab", "--evidence-file", str(evidence), "--format", "markdown")
        self.assertIn("Nothing was submitted", result.stdout)
        drafts = list((self.records / "lab" / "reports").glob("evidence-review-review.md"))
        self.assertEqual(len(drafts), 1)
        markdown = drafts[0].read_text(encoding="utf-8")
        self.assertIn("owner_control", markdown)
        self.assertIn("cross_read", markdown)
        self.assertNotIn("private-lab-token", markdown)

    def test_offline_plan_does_not_require_enabling_automation(self):
        self.cli("init", "manual", "--authorization", "manual testing only")
        self.cli("scope", "add", "manual", self.base)
        self.cli("tool-plan", "manual", "--tool", "sqlmap", "--url", self.base + "/search?q=1", "--parameter", "q")
        plans = list((self.records / "manual" / "raw" / "external-plans").glob("*.json"))
        plan = json.loads(plans[0].read_text())
        self.assertFalse(plan["automation_allowed_in_program"])
        self.assertFalse(plan["executed"])
        self.assertEqual(WorkflowLab.hits, [])

    def test_skill_json_plan_preflight_execution_and_reports(self):
        checkout = Path(__file__).resolve().parents[1]
        script = checkout / "skills" / "bugbounty-executor" / "scripts" / "run_plan.py"
        plan = self.root / "plan.json"
        plan.write_text(
            json.dumps({"program": "lab", "action": "request", "url": self.base + "/quiet", "params": ["page=2"]})
        )
        command = [
            sys.executable,
            str(script),
            "--toolkit-root",
            str(checkout),
            "--records-root",
            str(self.records),
            "--plan",
            str(plan),
        ]
        preview = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(WorkflowLab.hits, [])
        execution = subprocess.run(command + ["--execute"], capture_output=True, text=True, timeout=30)
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(WorkflowLab.hits, ["/quiet?page=2"])
        reports = self.records / "lab" / "reports"
        self.assertTrue((reports / "program-report.json").exists())
        self.assertTrue((reports / "program-report.html").exists())

    def test_uninitialized_or_automation_disabled_program_is_blocked(self):
        self.cli("request", "unknown", "--url", self.base, expected=1)
        self.cli("init", "manual", "--authorization", "manual testing only")
        self.cli("scope", "add", "manual", self.base)
        self.cli("fuzz", "manual", "--url", self.base + "/FUZZ", "--wordlist", "unused", expected=1)
        self.assertEqual(WorkflowLab.hits, [])

    def test_fuzz_dry_run_shows_bounded_plan_without_network(self):
        wordlist = self.root / "routes.txt"
        wordlist.write_text("api\norders\nadmin\n", encoding="utf-8")
        before = list(WorkflowLab.hits)
        preview = self.cli(
            "fuzz",
            "lab",
            "--url",
            self.base + "/FUZZ",
            "--wordlist",
            str(wordlist),
            "--max-tests",
            "2",
            "--dry-run",
        )
        self.assertEqual(WorkflowLab.hits, before)
        self.assertIn("selected inputs 1 (cap 1)", preview.stdout)
        self.assertIn("Planned upper bound: 2 requests including one baseline", preview.stdout)

    def test_active_fuzz_requires_confirmation_without_sending_baseline(self):
        wordlist = self.root / "routes.txt"
        wordlist.write_text("api\n", encoding="utf-8")
        before = list(WorkflowLab.hits)
        self.cli("fuzz", "lab", "--url", self.base + "/FUZZ", "--wordlist", str(wordlist), expected=1)
        self.assertEqual(WorkflowLab.hits, before)

    def test_bad_settings_and_program_name(self):
        config = self.root / "invalid.yaml"
        config.write_text("requests_per_second: 0\n")
        with self.assertRaises(ValueError):
            load_settings(config)
        with self.assertRaises(ValueError):
            ProgramPaths(self.root, "../escape")

    @unittest.skipUnless(shutil.which("ffuf"), "ffuf binary not installed; adapter unit tests still run")
    def test_real_ffuf_against_local_laboratory(self):
        wordlist = self.root / "words.txt"
        wordlist.write_text("search\nquiet\nmissing\nredirect\n")
        self.cli(
            "fuzz",
            "lab",
            "--url",
            self.base + "/FUZZ",
            "--wordlist",
            str(wordlist),
            "--match-codes",
            "200",
            "--confirm",
        )
        self.cli("report", "lab", "--format", "json")
        path = self.records / "lab" / "reports" / "program-report.json"
        report = json.loads(path.read_text())
        fuzz = next(item["data"] for item in report["evidence"] if "results" in item["data"])
        urls = {item["url"] for item in fuzz["results"]}
        self.assertEqual(urls, {self.base + "/search", self.base + "/quiet"})
        self.assertNotIn("/excluded", WorkflowLab.hits)
