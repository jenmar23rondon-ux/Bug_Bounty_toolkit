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
from bugbounty_toolkit.core.records import RecordStore, ProgramPaths


class WorkflowLab(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append(self.path)
        parsed = urlsplit(self.path)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/excluded")
            self.end_headers()
            return
        query = parse_qs(parsed.query)
        body = "no reflection"
        if parsed.path == "/search":
            body = "<html><body>" + " ".join(value for values in query.values() for value in values) + "</body></html>"
        if parsed.path == "/encoded":
            body = "<html>" + html.escape(" ".join(value for values in query.values() for value in values)) + "</html>"
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
        self.cli("init", "lab", "--authorization", "local laboratory owned for tests", "--automation-allowed", "--config", str(config))
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
        self.cli("xss", "lab", "--routes", str(routes), "--parameters", str(parameters), "--base-url", self.base, "--dry-run")
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

    def test_scope_and_rate_fail_before_network(self):
        self.cli("request", "lab", "--url", self.base + "/search", "--dry-run")
        self.cli("request", "lab", "--url", self.base + "/excluded", expected=1)
        self.cli("request", "lab", "--url", self.base + "/search", "--rate", "21", expected=1)
        self.assertEqual(WorkflowLab.hits, [])

    def test_skill_json_plan_preflight_execution_and_reports(self):
        checkout = Path(__file__).resolve().parents[1]
        script = checkout / "skills" / "bugbounty-executor" / "scripts" / "run_plan.py"
        plan = self.root / "plan.json"
        plan.write_text(json.dumps({"program": "lab", "action": "request", "url": self.base + "/quiet", "params": ["page=2"]}))
        command = [sys.executable, str(script), "--toolkit-root", str(checkout), "--records-root", str(self.records), "--plan", str(plan)]
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
        self.cli("fuzz", "lab", "--url", self.base + "/FUZZ", "--wordlist", str(wordlist), "--match-codes", "200")
        self.cli("report", "lab", "--format", "json")
        path = self.records / "lab" / "reports" / "program-report.json"
        report = json.loads(path.read_text())
        fuzz = next(item["data"] for item in report["evidence"] if "results" in item["data"])
        urls = {item["url"] for item in fuzz["results"]}
        self.assertEqual(urls, {self.base + "/search", self.base + "/quiet"})
        self.assertNotIn("/excluded", WorkflowLab.hits)
