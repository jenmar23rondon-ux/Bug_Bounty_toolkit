"""Context-aware fuzzing planner: offline HAR analysis, local wordlists, no auto-exec."""

from __future__ import annotations

import contextlib
import io
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.cli import build_parser, cmd_fuzz_plan
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.fuzzing.context_planner import (
    baseline_generic_recommendations,
    build_fuzz_plan,
    compare_recommendation_precision,
    load_har_for_planning,
    save_plan,
)
from bugbounty_toolkit.fuzzing.wordlist_manager import register_collection

REPO = Path(__file__).resolve().parents[1]
LAB_HAR = REPO / "labs" / "context_fuzz_lab" / "fixtures" / "capture.har"
LAB_WORDLISTS = REPO / "labs" / "context_fuzz_lab" / "wordlists"
GROUND = json.loads((REPO / "labs" / "context_fuzz_lab" / "ground_truth.json").read_text(encoding="utf-8"))
SECRET_MARK = "SYNTH-SECRET"


@contextlib.contextmanager
def no_network():
    def blocked(*_args, **_kwargs):
        raise AssertionError("network attempted during offline fuzz planning")

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(socket.socket, "connect", blocked))
        stack.enter_context(patch.object(socket.socket, "connect_ex", blocked))
        stack.enter_context(patch("socket.create_connection", blocked))
        stack.enter_context(patch("socket.getaddrinfo", blocked))
        yield


class ContextFuzzPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry = self.root / "wordlists.json"
        self.collection = register_collection(self.registry, "context-lab", LAB_WORDLISTS)
        self.program_root = self.root / "registros"
        self.store = RecordStore(ProgramPaths(self.program_root, "lab-program"))
        self.store.paths.scope_file.write_text("http://127.0.0.1:8191\n", encoding="utf-8")
        self.scope = ScopeValidator(self.store.paths.scope_file)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_analyze_capture_detects_api_params_and_tech_offline(self) -> None:
        with no_network():
            plan = build_fuzz_plan(
                "lab-program",
                LAB_HAR,
                collections=[self.collection],
                scope=self.scope,
                max_tests=20,
            )
        assert plan.context is not None
        self.assertEqual(plan.network_requests_sent, 0)
        self.assertFalse(plan.auto_execute)
        self.assertTrue(any(h.startswith("127.0.0.1") for h in plan.context.hosts))
        self.assertTrue(any(prefix.startswith("/api") for prefix in plan.context.route_prefixes))
        self.assertTrue(set(GROUND["observed_parameters"]).issubset(set(plan.context.parameters)))
        for marker in ("api", "json-api", "nginx", "versioned-api"):
            self.assertIn(marker, plan.context.technologies)
        self.assertIn("api", plan.context.categories_needed)
        self.assertIn("parameters", plan.context.categories_needed)

    def test_recommends_local_lists_and_excludes_passwords(self) -> None:
        with no_network():
            plan = build_fuzz_plan(
                "lab-program",
                LAB_HAR,
                collections=[self.collection],
                scope=self.scope,
                max_tests=20,
            )
        names = {Path(item.path).name for item in plan.recommendations}
        self.assertIn("api-endpoints.txt", names)
        self.assertIn("param-names.txt", names)
        self.assertNotIn("passwords.txt", names)
        discarded_names = {Path(str(row.get("path", ""))).name for row in plan.discarded if row.get("path")}
        self.assertIn("passwords.txt", discarded_names)
        blob = json.dumps(plan.to_dict())
        self.assertNotIn(SECRET_MARK, blob)
        self.assertNotIn("Bearer ", blob)

    def test_targets_are_scoped_and_budgeted(self) -> None:
        with no_network():
            plan = build_fuzz_plan(
                "lab-program",
                LAB_HAR,
                collections=[self.collection],
                scope=self.scope,
                category="api",
                max_tests=11,
                max_targets=5,
            )
        self.assertGreaterEqual(len(plan.targets), 1)
        for target in plan.targets:
            self.assertIn("FUZZ", target.url_template)
            self.assertEqual(target.max_entries, 10)
            self.assertEqual(target.estimated_requests, 11)
            self.assertTrue(target.host.startswith("127.0.0.1"))
            self.scope.require(target.url_template.replace("FUZZ", "probe"))
        # Out-of-scope host from a different capture must not survive.
        other = self.root / "other.har"
        other.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "t"},
                        "entries": [
                            {
                                "startedDateTime": "2026-01-01T00:00:00Z",
                                "request": {
                                    "method": "GET",
                                    "url": "https://out-of-scope.example/api/v1/x",
                                    "headers": [],
                                },
                                "response": {
                                    "status": 200,
                                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                                    "content": {"mimeType": "application/json", "text": "{}"},
                                },
                            }
                        ],
                    }
                }
            ),
            encoding="utf-8",
        )
        with no_network():
            blocked = build_fuzz_plan(
                "lab-program",
                other,
                collections=[self.collection],
                scope=self.scope,
                category="api",
                max_tests=10,
            )
        self.assertEqual(blocked.targets, [])
        self.assertTrue(any("scope" in str(row.get("reason", "")).lower() for row in blocked.discarded))

    def test_context_beats_generic_baseline_precision(self) -> None:
        relevant = set(GROUND["relevant_wordlist_names"]["api"])
        with no_network():
            plan = build_fuzz_plan(
                "lab-program",
                LAB_HAR,
                collections=[self.collection],
                scope=self.scope,
                category="api",
                max_tests=20,
            )
            before = baseline_generic_recommendations([self.collection], "api")
        # Generic baseline orders by size only; distractor soap list is smaller so it ranks first.
        self.assertEqual(Path(before[0].path).name, "soap-rpc-methods.txt")
        self.assertEqual(before[0].evidence, ("category-only",))
        # Context ranks by overlap with observed /api/v1 routes → api-endpoints first.
        self.assertEqual(Path(plan.recommendations[0].path).name, "api-endpoints.txt")
        after_top1 = compare_recommendation_precision(
            recommended=plan.recommendations[:1],
            relevant_paths=relevant,
        )
        before_top1 = compare_recommendation_precision(recommended=before[:1], relevant_paths=relevant)
        self.assertEqual(before_top1["precision"], 0.0)
        self.assertEqual(after_top1["precision"], 1.0)
        self.assertTrue(all(item.evidence and item.evidence != ("category-only",) for item in plan.recommendations))

    def test_object_association_never_confirms(self) -> None:
        with no_network():
            plan = build_fuzz_plan(
                "lab-program",
                LAB_HAR,
                collections=[self.collection],
                scope=self.scope,
                max_tests=20,
                object_candidates=[
                    {
                        "endpoint": "/api/v1/orders/{id}",
                        "object_ref": "obj-" + "a" * 24,
                        "resource_type": "order",
                    }
                ],
                object_key=b"0123456789abcdef0123456789abcdef",
            )
        self.assertGreaterEqual(len(plan.object_associations), 1)
        self.assertTrue(all(item.confirmed is False for item in plan.object_associations))
        self.assertTrue(all("structural_path_match" in item.basis for item in plan.object_associations))

    def test_save_plan_wires_investigation_memory(self) -> None:
        with no_network():
            plan = build_fuzz_plan(
                "lab-program",
                LAB_HAR,
                collections=[self.collection],
                scope=self.scope,
                category="api",
                max_tests=10,
            )
            result = save_plan(self.store, plan)
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertFalse(result["plan_executed"])
        self.assertTrue(Path(result["evidence"]).exists())
        evidence = json.loads(Path(result["evidence"]).read_text(encoding="utf-8"))
        self.assertEqual(evidence["type"], "context-aware-fuzz-plan")
        self.assertNotIn(SECRET_MARK, json.dumps(evidence))
        self.assertIsNotNone(result["investigation_id"])

    def test_cli_dry_run_is_offline_and_writes_nothing_by_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "--records-root",
                str(self.program_root),
                "fuzz-plan",
                "lab-program",
                "--har",
                str(LAB_HAR),
                "--registry",
                str(self.registry),
                "--max-tests",
                "15",
                "--category",
                "api",
                "--dry-run",
            ]
        )
        # Rebind store paths via records-root: cmd uses global RECORDS_ROOT from main; call after setting.
        import bugbounty_toolkit.cli as cli

        cli.RECORDS_ROOT = self.program_root
        out = io.StringIO()
        with no_network(), contextlib.redirect_stdout(out):
            cmd_fuzz_plan(args)
        text = out.getvalue()
        self.assertIn('"network_requests_sent": 0', text)
        self.assertIn("[dry-run]", text)
        self.assertNotIn(SECRET_MARK, text)
        # No evidence written on dry-run without --output.
        evidence_files = list((self.store.paths.evidence_dir / "fuzzing").glob("*fuzz-plan*"))
        self.assertEqual(evidence_files, [])

    def test_planner_rejects_tiny_budget_and_bad_category(self) -> None:
        with no_network():
            with self.assertRaisesRegex(ValueError, "between 2"):
                build_fuzz_plan(
                    "lab-program",
                    LAB_HAR,
                    collections=[self.collection],
                    scope=self.scope,
                    max_tests=1,
                )
            with self.assertRaisesRegex(ValueError, "Unknown discovery category"):
                build_fuzz_plan(
                    "lab-program",
                    LAB_HAR,
                    collections=[self.collection],
                    scope=self.scope,
                    category="passwords",
                    max_tests=10,
                )

    def test_load_har_partial_recovery_surface(self) -> None:
        with no_network():
            result = load_har_for_planning(LAB_HAR)
        self.assertGreaterEqual(result.summary()["accepted"], 8)
        self.assertEqual(result.summary()["mode"], "partial")


class ContextFuzzLabServerTests(unittest.TestCase):
    def test_lab_server_loopback_only_and_known_routes(self) -> None:
        from bugbounty_toolkit.context_fuzz_lab_server import KNOWN_ROUTES, make_server
        import urllib.error
        import urllib.request

        with self.assertRaises(ValueError):
            make_server("8.8.8.8", 8191)
        server = make_server("127.0.0.1", 0)
        host, port = server.server_address[:2]
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for route in ("/healthz", "/api/v1/orders"):
                with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=2) as response:
                    body = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.status, 200)
                self.assertIn(route, KNOWN_ROUTES)
                self.assertIsInstance(body, dict)
            try:
                urllib.request.urlopen(f"http://{host}:{port}/api/v1/admin", timeout=2)
                self.fail("protected route should not return success")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 401)
            with urllib.request.urlopen(f"http://{host}:{port}/api/v1/wildcard/x", timeout=2) as response:
                self.assertEqual(json.loads(response.read().decode())["wildcard"], True)
        finally:
            server.shutdown()
            server.server_close()

    def test_lab_server_rejects_non_ip_host_and_bad_port(self) -> None:
        from bugbounty_toolkit.context_fuzz_lab_server import make_server

        with self.assertRaises(ValueError):
            make_server("localhost", 8191)
        with self.assertRaises(ValueError):
            make_server("127.0.0.1", -1)


if __name__ == "__main__":
    unittest.main()
