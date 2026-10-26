from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.dashboard_triage import FORBIDDEN_ACTIONS, build_triage, mask_display_secrets

try:
    from fastapi.testclient import TestClient

    from bugbounty_toolkit.dashboard import create_app
    from labs.dashboard_triage_lab.run_lab import CANARIES, build_lab, run
except ImportError:  # pragma: no cover - optional dashboard extra absent
    TestClient = None  # type: ignore[assignment,misc]


@unittest.skipIf(TestClient is None, "Install the optional .[dashboard] dependencies to run dashboard tests.")
class DashboardTriageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        build_lab(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def client(self, program: str) -> TestClient:
        return TestClient(create_app(self.root, program), base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000))

    def test_lab_metrics_have_no_leaks_or_misread_states(self) -> None:
        with tempfile.TemporaryDirectory() as other:
            result = run(Path(other), repetitions=2)
        metrics = result["metrics"]
        self.assertEqual(metrics["canaries_leaked"], [])
        self.assertEqual(metrics["state_interpretation_errors"], 0)
        self.assertEqual(metrics["top_candidate_correct"], metrics["scenarios"])
        self.assertEqual(metrics["broken_references_shown"], metrics["broken_references_expected"])
        self.assertEqual(metrics["security_checks_passed"], metrics["security_checks_total"])
        self.assertEqual(result["network_requests_sent"], 0)

    def test_model_confirmation_is_never_displayed_as_confirmed(self) -> None:
        triage = build_triage(ProgramPaths(self.root, "invalid-references"))
        row = next(r for r in triage["candidates"] if r["candidate_id"] == "c-fake-confirmed")
        self.assertEqual(row["ledger_state"], "confirmed")
        self.assertEqual(row["displayed_state"], "requires_validation")
        self.assertFalse(row["confirmed"])
        self.assertTrue(row["warnings"])
        self.assertFalse(triage["ledger_valid"])
        self.assertGreaterEqual(triage["broken_references"], 2)

    def test_human_confirmation_with_fresh_evidence_is_shown(self) -> None:
        triage = build_triage(ProgramPaths(self.root, "multi-candidates"))
        row = next(r for r in triage["candidates"] if r["candidate_id"] == "c-cors-confirmed")
        self.assertTrue(row["confirmed"])
        self.assertEqual(triage["candidates"][0]["candidate_id"], "c-idor-orders")
        self.assertEqual(triage["candidates"][0]["idor_flow"]["stage"], "awaiting_controls_documented")
        self.assertEqual(triage["coverage"]["surface_status"]["blocked"], 1)
        self.assertEqual(sorted(FORBIDDEN_ACTIONS), sorted(triage["forbidden_actions"]))

    def test_filters_and_validation(self) -> None:
        paths = ProgramPaths(self.root, "multi-candidates")
        self.assertEqual(build_triage(paths, category="xss")["counts"]["shown"], 1)
        self.assertEqual(build_triage(paths, state="confirmed")["counts"]["shown"], 1)
        self.assertEqual(build_triage(paths, evidence="missing")["counts"]["shown"], 0)
        for kwargs in ({"state": "x"}, {"evidence": "x"}, {"category": "../x"}):
            with self.assertRaises(ValueError):
                build_triage(paths, **kwargs)  # type: ignore[arg-type]

    def test_empty_and_malformed_ledger_states(self) -> None:
        empty = build_triage(ProgramPaths(self.root, "no-candidates"))
        self.assertEqual(empty["ledger_status"], "absent")
        self.assertIn("ledger init", empty["message"])
        paths = ProgramPaths(self.root, "rejected")
        (paths.program_dir / "ledger" / "evidence-ledger.json").write_text("{not json", encoding="utf-8")
        broken = build_triage(paths)
        self.assertEqual(broken["ledger_status"], "error")
        self.assertEqual(broken["candidates"], [])

    def test_detail_withholds_paths_and_bodies(self) -> None:
        with self.client("multi-candidates") as client:
            response = client.get("/api/triage/candidates/c-idor-orders")
            self.assertEqual(response.status_code, 200)
            text = response.text
            for canary in CANARIES:
                self.assertNotIn(canary, text)
            self.assertNotIn("evidence/", text)
            self.assertEqual(client.get("/api/triage/candidates/nope").status_code, 404)
            self.assertEqual(client.get("/api/triage/candidates/bad%20id").status_code, 400)

    def test_ai_runs_and_review_queue_views(self) -> None:
        with self.client("ai-discrepancy") as client:
            ai = client.get("/api/triage/ai-reviews").json()
            self.assertEqual(ai["disputed_evidence"], ["e2"])
            self.assertFalse(ai["consensus_is_proof"])
        with self.client("reviewable-reports") as client:
            runs = client.get("/api/triage/runs").json()
            self.assertTrue(runs["comparison"]["available"])
            self.assertEqual(runs["comparison"]["added"], ["g-new"])
            queue = client.get("/api/triage/review-queue").json()
            self.assertTrue(queue["ready_for_review"])
            self.assertEqual(queue["candidates_awaiting_human_review"], ["c-report"])
        with self.client("no-candidates") as client:
            self.assertIsNone(client.get("/api/triage/ai-reviews").json()["latest"])
            self.assertFalse(client.get("/api/triage/runs").json()["comparison"]["available"])

    def test_overview_withholds_run_paths_and_secrets(self) -> None:
        paths = ProgramPaths(self.root, "rejected")
        store = RecordStore(paths)
        store.connection.execute(
            "insert into runs(started_at,command_name,target,command,return_code,output_path) values(?,?,?,?,?,?)",
            ("now", "nuclei", "t", "nuclei -H 'Authorization: Bearer SECRETRUN123'", 2, "/home/u/private/out.txt"),
        )
        store.connection.commit()
        store.close()
        with self.client("rejected") as client:
            text = client.get("/api/overview").text
            self.assertNotIn("SECRETRUN123", text)
            self.assertNotIn("/home/u/private", text)
            progress = client.get("/api/triage/runs").json()["progress"]
            self.assertEqual(progress["technical_errors"], 1)

    def test_mask_display_secrets(self) -> None:
        masked = mask_display_secrets("cookie: sid=abc; Authorization: Basic Zm9vOmJhcg== ok")
        self.assertNotIn("Zm9vOmJhcg", masked)
        self.assertIn("ok", masked)


if __name__ == "__main__":
    unittest.main()
