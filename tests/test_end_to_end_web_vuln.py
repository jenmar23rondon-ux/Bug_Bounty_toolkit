from __future__ import annotations

import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.api_workflow import build_api_workflow
from bugbounty_toolkit.analysis.evidence_engine import import_evidence
from bugbounty_toolkit.analysis.hypotheses import analyze_hypotheses
from bugbounty_toolkit.analysis.skill_router import route_hypotheses
from bugbounty_toolkit.core.http_client import HttpClient, RequestSpec
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.reporting.finding_report import (
    build_evidence_finding_report,
    render_evidence_report_json,
    render_evidence_report_markdown,
)
from bugbounty_toolkit.sqli.parameter_tester import SqliOptions, SqliParameterTester
from bugbounty_toolkit.utils.exceptions import ToolkitError
from bugbounty_toolkit.web_vuln_lab_server import make_server
from bugbounty_toolkit.xss.parameter_tester import XssOptions, XssParameterTester


def _model_response(messages: list[dict[str, str]], *_args: object) -> str:
    prompt = messages[-1]["content"]
    packet = json.loads(prompt[prompt.find("{") :])
    endpoint = packet["endpoint"]["path_template"]
    category = "xss" if endpoint.startswith("/xss/") else "sqli"
    fingerprints = packet["fingerprints"]
    evidence_id = fingerprints[0]["record_id"]
    return json.dumps(
        {
            "category": category,
            "summary": "The local fixture produced a bounded signal that needs independent validation.",
            "evidence_for": [{"record_id": evidence_id, "why": "A fixture response fingerprint was observed."}],
            "evidence_against": [],
            "missing_controls": ["The fixture is simulated and does not establish production behavior."],
            "confidence": "low",
            "next_check": {
                "kind": "offline",
                "suggestion": "Review the fixture response and its negative controls.",
                "why": "A model hypothesis is not confirmation.",
            },
            "status": "hypothesis",
        }
    )


class EndToEndWebVulnerabilityLabTests(unittest.TestCase):
    def test_cli_dry_run_only_prints_the_local_workflow(self) -> None:
        args = cli.build_parser().parse_args(["lab", "web-vuln", "--dry-run"])
        output = StringIO()
        with patch("bugbounty_toolkit.cli.subprocess.run") as run, redirect_stdout(output):
            args.func(args)
        run.assert_not_called()
        self.assertIn("127.0.0.1", output.getvalue())
        self.assertIn("real SQL engine", output.getvalue())

    def test_xss_sqli_evidence_hypotheses_router_and_reports(self) -> None:
        try:
            server = make_server("127.0.0.1", 0)
        except OSError as exc:
            if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 10013:
                self.skipTest(f"The test environment denied loopback binding: {exc}")
            raise
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        origin = f"http://127.0.0.1:{port}"

        try:
            temporary_parent = Path(__file__).resolve().parents[1] / ".test-tmp"
            temporary_parent.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="bbtk-web-vuln-", dir=temporary_parent) as temporary:
                root = Path(temporary)
                scope_path = root / "scope.txt"
                scope_path.write_text("127.0.0.1\n", encoding="utf-8")
                routes_dir = root / "routes"
                routes_dir.mkdir()
                evidence_dir = root / "evidence"
                scope = ScopeValidator(scope_path)
                client = HttpClient(scope, timeout=2.0, rate_limiter=RateLimiter(250.0))
                artifacts: list[Path] = []
                self.assertEqual(client.send(RequestSpec("GET", origin + "/healthz")).status_code, 200)
                self.assertEqual(client.send(RequestSpec("GET", origin + "/not-a-fixture")).status_code, 404)

                xss_cases = {
                    "reflected": ("/xss/reflected?q=seed&mode=reflect", 1),
                    "escaped": ("/xss/escaped?q=seed", 3),
                    "ambiguous": ("/xss/ambiguous?q=seed", 1),
                    "missing": ("/xss/reflected?q=seed&mode=missing", 1),
                }
                xss_rows: dict[str, list[dict[str, object]]] = {}
                for name, (path, budget) in xss_cases.items():
                    route_file = routes_dir / f"xss-{name}.txt"
                    route_file.write_text(origin + path + "\n", encoding="utf-8")
                    parameter_file = routes_dir / f"xss-{name}-params.txt"
                    parameter_file.write_text("q\n", encoding="utf-8")
                    artifact, rows = XssParameterTester(scope, client).run(
                        XssOptions(route_file, parameter_file, max_tests=budget),
                        evidence_dir / f"xss-{name}",
                    )
                    artifacts.append(artifact)
                    xss_rows[name] = rows

                reflected = xss_rows["reflected"][0]
                self.assertEqual(reflected["classification"], "possible", reflected)
                self.assertTrue(reflected["reflected"])
                self.assertFalse(reflected["confirmed"])
                escaped = xss_rows["escaped"][-1]
                self.assertFalse(escaped["reflected_unescaped"])
                self.assertFalse(escaped["confirmed"])
                self.assertEqual(xss_rows["ambiguous"][0]["content_type"], "application/json")
                self.assertFalse(xss_rows["ambiguous"][0]["confirmed"])
                self.assertEqual(xss_rows["missing"][0]["classification"], "not_reproducible")

                sqli_cases = {
                    "vulnerable": "/sqli/vulnerable?q=seed",
                    "protected": "/sqli/protected?q=seed",
                    "ambiguous": "/sqli/ambiguous?q=seed",
                }
                sqli_rows: dict[str, list[dict[str, object]]] = {}
                for name, path in sqli_cases.items():
                    route_file = routes_dir / f"sqli-{name}.txt"
                    route_file.write_text(origin + path + "\n", encoding="utf-8")
                    parameter_file = routes_dir / f"sqli-{name}-params.txt"
                    parameter_file.write_text("q\n", encoding="utf-8")
                    artifact, rows = SqliParameterTester(scope, client).run(
                        SqliOptions(route_file, parameter_file, max_tests=3),
                        evidence_dir / f"sqli-{name}",
                    )
                    artifacts.append(artifact)
                    sqli_rows[name] = rows

                vulnerable = sqli_rows["vulnerable"]
                self.assertTrue(any(row["classification"] == "possible" for row in vulnerable))
                self.assertFalse(any(row.get("confirmed") is True for row in vulnerable))
                self.assertFalse(any(row["classification"] == "possible" for row in sqli_rows["protected"]))
                self.assertFalse(any(row["classification"] == "possible" for row in sqli_rows["ambiguous"]))

                bundle = import_evidence(artifacts)
                bundle_path = root / "unified-evidence.json"
                bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
                source_tools = {tool for record in bundle["records"] for tool in record["source_tools"]}
                self.assertTrue({"xss", "sqli"}.issubset(source_tools))
                self.assertTrue(all("q" in record["parameters"] for record in bundle["records"]))
                self.assertTrue(all(record["endpoint"] for record in bundle["records"]))

                workflow = build_api_workflow(bundle_path)
                endpoint_nodes = [node for node in workflow["nodes"] if node["type"] == "Endpoint"]
                self.assertTrue(any(node["path_template"] == "/xss/reflected" for node in endpoint_nodes))
                self.assertTrue(
                    any(node["path_template"] == "/sqli/vulnerable" for node in endpoint_nodes), endpoint_nodes
                )

                with patch("bugbounty_toolkit.analysis.hypotheses.chat_with_ollama", side_effect=_model_response):
                    hypotheses_result = analyze_hypotheses(bundle_path, timeout=1.0)
                hypotheses = [
                    (row["group_id"], row["hypothesis"])
                    for row in hypotheses_result["groups"]
                    if row.get("status") == "reviewed" and isinstance(row.get("hypothesis"), dict)
                ]
                categories = {hypothesis["category"] for _, hypothesis in hypotheses}
                self.assertTrue({"xss", "sqli"}.issubset(categories))
                routed = route_hypotheses({}, hypotheses, "local-web-lab", 100, use_ollama=False)
                selected_skills = {row["skill"] for row in routed["selected"]}
                self.assertIn("bugbounty-xss", selected_skills)
                self.assertIn("bugbounty-sqli", selected_skills)
                self.assertTrue(all("--dry-run" in row["command"] for row in routed["plan"]))

                reports_dir = root / "reports"
                reports_dir.mkdir()
                rendered_categories: set[str] = set()
                for index, (_group_id, hypothesis) in enumerate(hypotheses, start=1):
                    report = build_evidence_finding_report(
                        {
                            "type": hypothesis["category"],
                            "classification": "possible",
                            "summary": hypothesis["summary"],
                            "endpoint": next(
                                node["path_template"]
                                for node in endpoint_nodes
                                if node["path_template"].startswith(f"/{hypothesis['category']}/")
                            ),
                            "host": "127.0.0.1",
                            "evidence_for": hypothesis["evidence_for"],
                            "evidence_against": hypothesis["evidence_against"],
                            "limitations": ["Deterministic local fixture; no production vulnerability is asserted."],
                        },
                        program="local-web-lab",
                    )
                    rendered_categories.add(str(report["category"]))
                    json_path = reports_dir / f"finding-{index}.json"
                    render_evidence_report_json(report, json_path)
                    markdown_path = reports_dir / f"finding-{index}.md"
                    markdown_path.write_text(render_evidence_report_markdown(report), encoding="utf-8")
                    self.assertIn("Draft only", markdown_path.read_text(encoding="utf-8"))
                    self.assertFalse(report["submitted"])
                self.assertTrue({"xss", "sqli"}.issubset(rendered_categories))
                self.assertGreaterEqual(len(list(reports_dir.glob("*.json"))), 2)
        except ToolkitError as exc:
            cause = exc.__cause__
            reason = getattr(cause, "reason", None)
            if any(
                isinstance(candidate, PermissionError) or getattr(candidate, "winerror", None) == 10013
                for candidate in (cause, reason)
            ):
                self.skipTest(f"The test environment denied loopback HTTP: {exc}")
            raise
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

    def test_lab_rejects_non_loopback_bind_and_labels_simulated_database(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            make_server("0.0.0.0", 8181)
        source = Path(__file__).resolve().parents[1] / "bugbounty_toolkit" / "web_vuln_lab_server.py"
        code = source.read_text(encoding="utf-8")
        self.assertIn("no database", code)
        self.assertIn("simulate", code)

    def test_fixture_server_requires_loopback_ip_literal(self) -> None:
        for host in ("localhost", "example.invalid", "::"):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "loopback"):
                make_server(host, 8181)


if __name__ == "__main__":
    unittest.main()
