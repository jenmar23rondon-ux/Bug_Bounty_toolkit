from __future__ import annotations

import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.investigation_memory import InvestigationMemory
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore

try:
    from fastapi.testclient import TestClient

    from bugbounty_toolkit.dashboard import create_app, require_loopback_host
except ImportError:  # pragma: no cover - exercised when optional dashboard extra is absent
    TestClient = None  # type: ignore[assignment,misc]
    create_app = None  # type: ignore[assignment]
    require_loopback_host = None  # type: ignore[assignment]


@unittest.skipIf(TestClient is None, "Install the optional .[dashboard] dependencies to run dashboard tests.")
class DashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.records_root = self.root / "records"
        self.paths = ProgramPaths(self.records_root, "dashboard-lab")
        self.client = TestClient(
            create_app(self.records_root, "dashboard-lab"),
            base_url="http://127.0.0.1:8765",
            client=("127.0.0.1", 50000),
        )

    def tearDown(self) -> None:
        self.client.close()
        self.temporary.cleanup()

    def test_dashboard_is_loopback_only_and_has_no_public_bind(self) -> None:
        self.assertEqual(require_loopback_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(require_loopback_host("::1"), "::1")
        with self.assertRaisesRegex(ValueError, "loopback"):
            require_loopback_host("0.0.0.0")
        response = self.client.get("/", headers={"host": "attacker.example"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("loopback", response.json()["detail"])

    def test_overview_lists_saved_investigation_without_exposing_event_payloads(self) -> None:
        snapshot_path = self.paths.program_dir / "evidence" / "ai-investigations" / "review.json"
        snapshot_path.parent.mkdir(parents=True)
        snapshot_path.write_text(
            json.dumps(
                {
                    "hypotheses": {
                        "groups": [
                            {
                                "group_id": "group-1",
                                "status": "reviewed",
                                "hypothesis": {"category": "access_control", "summary": "Review ownership."},
                            }
                        ]
                    },
                    "prioritization": {"steps": [{"kind": "http", "why": "A negative control is missing."}]},
                    "access_control_assessment": {"classification": "insufficient_evidence"},
                }
            ),
            encoding="utf-8",
        )
        store = RecordStore(self.paths)
        try:
            InvestigationMemory(store).save_snapshot(
                "web-review", "a" * 24, "evidence/ai-investigations/review.json", {"route": {"status": "ready"}}
            )
        finally:
            store.close()
        response = self.client.get("/api/overview")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["investigations"][0]["investigation_id"], "web-review")
        self.assertNotIn("events", result["investigations"][0])
        detail = self.client.get("/api/investigations/web-review")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["status"], "active")
        review = self.client.get("/api/hypotheses").json()
        self.assertEqual(review["hypotheses"][0]["hypothesis"]["category"], "access_control")
        self.assertEqual(review["controls_pending"][0]["kind"], "http")
        self.assertEqual(review["access_control_assessment"]["classification"], "insufficient_evidence")

        self.paths.reports_dir.mkdir(parents=True, exist_ok=True)
        (self.paths.reports_dir / "benchmark.json").write_text(
            json.dumps({"type": "bbtk-benchmark", "case_count": 12}), encoding="utf-8"
        )
        benchmark = self.client.get("/api/benchmark").json()
        self.assertEqual(benchmark["latest"]["case_count"], 12)

    def test_cli_starts_only_on_loopback(self) -> None:
        original_root = cli.RECORDS_ROOT
        cli.RECORDS_ROOT = self.records_root
        try:
            args = cli.build_parser().parse_args(["dashboard", "dashboard-lab"])
            with patch("uvicorn.run") as run, redirect_stdout(io.StringIO()):
                args.func(args)
            self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
            args = cli.build_parser().parse_args(["dashboard", "dashboard-lab", "--host", "0.0.0.0"])
            with self.assertRaisesRegex(ValueError, "loopback"):
                args.func(args)
        finally:
            cli.RECORDS_ROOT = original_root

    def test_evidence_import_redacts_burp_session_and_indexes_graph_offline(self) -> None:
        raw_request = (
            "GET /api/orders/1042?view=summary HTTP/1.1\r\n"
            "Host: 127.0.0.1:8099\r\nCookie: session=dashboard-secret\r\n\r\n"
        )
        raw_response = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"order":"test"}'
        xml = (
            "<items><item><url>http://127.0.0.1:8099/api/orders/1042?view=summary</url>"
            f'<request base64="true">{base64.b64encode(raw_request.encode()).decode()}</request>'
            f'<response base64="true">{base64.b64encode(raw_response.encode()).decode()}</response>'
            "</item></items>"
        )
        response = self.client.post(
            "/api/evidence/import?filename=capture.xml",
            content=xml.encode(),
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertEqual(result["ollama_calls"], 0)
        self.assertFalse(result["active_checks_executed"])
        self.assertGreater(result["summary"]["records_unique"], 0)
        saved_bundle = self.paths.program_dir / Path(*Path(result["bundle_path"]).parts)
        serialized = saved_bundle.read_text(encoding="utf-8")
        self.assertNotIn("dashboard-secret", serialized)
        self.assertIn('"source_path": "capture.xml"', serialized)
        graph = self.client.get("/api/graph/search", params={"endpoint": "/api/orders/{id}"})
        self.assertEqual(graph.status_code, 200, graph.text)
        self.assertTrue(graph.json()["matches"])

    def test_reports_are_browsable_as_text_and_download_as_attachments(self) -> None:
        self.paths.reports_dir.mkdir(parents=True)
        report = self.paths.reports_dir / "review.html"
        report.write_text("<script>untrusted()</script>", encoding="utf-8")
        listed = self.client.get("/api/reports").json()["reports"]
        self.assertEqual(listed, [{"name": "review.html", "format": "html"}])
        content = self.client.get("/api/reports/review.html/content")
        self.assertEqual(content.headers["content-type"], "text/plain; charset=utf-8")
        self.assertIn("<script>", content.text)
        download = self.client.get("/api/reports/review.html")
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers["content-disposition"])
        self.assertEqual(self.client.get("/api/reports/%2e%2e%2fsecret.json/content").status_code, 404)

    def test_wordlist_dashboard_shows_local_metadata_without_reading_entries(self) -> None:
        registry = self.root / "wordlists.json"
        registry.write_text("[]", encoding="utf-8")
        collections = [SimpleNamespace(name="SecLists", category=None)]
        entries = [
            SimpleNamespace(collection="SecLists", path=Path("api-endpoints.txt"), category="api", size_bytes=128),
            SimpleNamespace(collection="SecLists", path=Path("common.txt"), category="directories", size_bytes=256),
        ]
        with (
            patch("bugbounty_toolkit.dashboard.default_registry_path", return_value=registry),
            patch("bugbounty_toolkit.dashboard.load_collections", return_value=collections),
            patch("bugbounty_toolkit.dashboard.list_wordlists", return_value=entries),
        ):
            response = self.client.get("/api/wordlists")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["wordlist_count"], 2)
        self.assertEqual(result["total_size_bytes"], 384)
        self.assertEqual(result["counts_by_category"], {"api": 1, "directories": 1})
        self.assertFalse(result["contents_read"])
        self.assertNotIn(str(self.root), response.text)

    def test_discovery_dashboard_redacts_output_paths_and_templates_resource_ids(self) -> None:
        directory = self.paths.evidence_dir / "fuzzing"
        directory.mkdir(parents=True)
        artifact = directory / "20261025T120000-ffuf.json"
        artifact.write_text(
            json.dumps(
                {
                    "type": "ffuf",
                    "raw_output": "C:/private/raw.json",
                    "log": "C:/private/ffuf.log",
                    "limits": {"planned_requests_upper_bound": 5, "ffuf_requests_observed": None},
                    "results": [
                        {
                            "url": "https://target.example/api/orders/123?token=secret",
                            "status": 200,
                            "classification": "endpoint_candidate",
                            "response_group": "response-0001",
                        }
                    ],
                    "followup_candidates": [
                        {
                            "route_template": "/api/orders/{id}",
                            "resource_privacy": "unknown",
                            "vulnerability_confirmed": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        response = self.client.get("/api/discovery")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["results"][0]["endpoint"], "/api/orders/{id}")
        self.assertEqual(result["authorization_followups"][0]["vulnerability_confirmed"], False)
        self.assertNotIn("C:/private", response.text)
        self.assertNotIn("token=secret", response.text)

    def test_access_matrix_dashboard_exposes_only_boolean_predicates(self) -> None:
        directory = self.paths.evidence_dir / "access-control"
        directory.mkdir(parents=True)
        (directory / "access.json").write_text(
            json.dumps(
                {
                    "type": "access-control",
                    "mode": "account-matrix",
                    "classification": "candidate",
                    "controls_valid": True,
                    "matrix_accounts": ["owner", "actor"],
                    "matrix": [
                        {
                            "session_account": "actor",
                            "resource_owner": "owner",
                            "access_type": "cross",
                            "classification": "candidate",
                            "private_resource_match": True,
                            "resource_id": "private-id-123",
                            "marker": "private-marker-secret",
                        }
                    ],
                    "steps": [
                        {
                            "step": "cross_actor_to_owner",
                            "application_success": True,
                            "owner_resource_match": True,
                            "owner_private_match": True,
                            "body": "private response body",
                        }
                    ],
                    "stop_reason": "private_evidence_observed",
                }
            ),
            encoding="utf-8",
        )
        response = self.client.get("/api/access-matrix")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["matrix"][0]["classification"], "candidate")
        self.assertTrue(result["matrix"][0]["private_resource_match"])
        self.assertFalse(result["confirmed"])
        self.assertFalse(result["matrix"][0]["confirmed"])
        self.assertNotIn("private-id-123", response.text)
        self.assertNotIn("private-marker-secret", response.text)
        self.assertNotIn("private response body", response.text)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertIn("/api/access-matrix", self.client.get("/").text)

    def test_upload_validates_name_type_and_empty_body(self) -> None:
        headers = {"content-type": "application/octet-stream"}
        self.assertEqual(
            self.client.post("/api/evidence/import?filename=../bad.json", content=b"{} ", headers=headers).status_code,
            400,
        )
        self.assertEqual(
            self.client.post("/api/evidence/import?filename=artifact.exe", content=b"x", headers=headers).status_code,
            415,
        )
        self.assertEqual(
            self.client.post("/api/evidence/import?filename=empty.json", content=b"", headers=headers).status_code,
            400,
        )

    def test_upload_rejects_foreign_origin_and_simple_form_content(self) -> None:
        foreign = self.client.post(
            "/api/evidence/import?filename=artifact.json",
            content=b"{}",
            headers={"content-type": "application/octet-stream", "origin": "https://attacker.example"},
        )
        self.assertEqual(foreign.status_code, 403)
        form = self.client.post(
            "/api/evidence/import?filename=artifact.json",
            content=b"payload=x",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(form.status_code, 415)


if __name__ == "__main__":
    unittest.main()
