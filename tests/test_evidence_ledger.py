from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis import evidence_ledger as L
from bugbounty_toolkit.analysis.evidence_ledger_lab import SCENARIOS, run_evidence_ledger_lab
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.reporting.json_report import build_program_report

SCHEMA_DOC = Path(__file__).resolve().parents[1] / "docs" / "schemas" / "evidence-ledger-v1.schema.json"


class EvidenceLedgerLabTests(unittest.TestCase):
    def test_lab_catches_every_invalid_scenario_with_zero_false_confirmations(self) -> None:
        result = run_evidence_ledger_lab()
        metrics = result["metrics"]
        failed = [row["scenario"] for row in result["scenarios"] if not row["passed"]]
        self.assertEqual(failed, [])
        self.assertEqual(metrics["scenarios_passed"], len(SCENARIOS))
        self.assertEqual(metrics["false_confirmations"], 0)
        self.assertEqual(metrics["legacy_vulnerable_import_state"], "candidate")
        self.assertEqual(metrics["api_guards_held"], "5/5")
        self.assertEqual(
            metrics["coverage_recorded"],
            {"investigated": 1, "reviewed": 1, "pending": 1, "blocked": 1, "out_of_scope": 1},
        )
        self.assertEqual(metrics["coverage_ratio"], 0.5)
        self.assertEqual(metrics["network_requests_sent"], 0)


class EvidenceLedgerUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.program_dir = ProgramPaths(self.root, "unit").program_dir
        (self.program_dir / "evidence").mkdir(parents=True)
        (self.program_dir / "evidence" / "a.json").write_text('{"x": 1}', encoding="utf-8")
        self.ledger = L.new_ledger("unit")
        L.upsert_surface(self.ledger, {"surface_id": "s1", "kind": "endpoint", "ref": "/a", "status": "investigated"})
        L.add_evidence(self.ledger, self.program_dir, "e1", "evidence/a.json", tool="manual")
        L.add_candidate(self.ledger, "c1", "s1", "idor", "alice", ["e1"])

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_new_candidate_starts_unconfirmed_and_is_valid(self) -> None:
        self.assertEqual(self.ledger["candidates"][0]["state"], "candidate")
        self.assertTrue(L.validate_ledger(self.ledger, program_dir=self.program_dir)["valid"])

    def test_full_human_path_to_confirmed(self) -> None:
        L.review_candidate(self.ledger, "c1", "requires_validation", "bob", blockers=["replay"])
        with self.assertRaises(L.LedgerError):
            L.review_candidate(self.ledger, "c1", "confirmed", "bob", method="human_manual", basis="b")
        L.review_candidate(
            self.ledger, "c1", "confirmed", "bob", method="human_manual", basis="replayed", human_attestation=True
        )
        result = L.validate_ledger(self.ledger, program_dir=self.program_dir)
        self.assertTrue(result["valid"], result["issues"])
        self.assertEqual(self.ledger["candidates"][0]["history"][-1]["from"], "requires_validation")

    def test_self_confirmation_is_rejected_by_validator(self) -> None:
        L.review_candidate(self.ledger, "c1", "requires_validation", "alice", blockers=["replay"])
        L.review_candidate(
            self.ledger, "c1", "confirmed", "alice", method="human_manual", basis="me", human_attestation=True
        )
        codes = {i["code"] for i in L.validate_ledger(self.ledger)["issues"]}
        self.assertIn("review_not_independent", codes)

    def test_save_refuses_invalid_ledger(self) -> None:
        self.ledger["candidates"][0]["evidence_refs"] = ["ghost"]
        with self.assertRaises(L.LedgerError):
            L.save_ledger(self.root / "l.json", self.ledger)
        self.assertFalse((self.root / "l.json").exists())

    def test_rejection_and_reopen(self) -> None:
        L.review_candidate(
            self.ledger, "c1", "rejected", "bob", rejection_reason="not_reproducible", rejection_detail="no diff"
        )
        self.assertTrue(L.validate_ledger(self.ledger)["valid"])
        L.review_candidate(self.ledger, "c1", "candidate", "bob")
        self.assertNotIn("rejection", self.ledger["candidates"][0])

    def test_markdown_render_mentions_states(self) -> None:
        text = L.render_markdown(self.ledger, L.validate_ledger(self.ledger))
        self.assertIn("| c1 | s1 | idor | candidate | e1 |", text)
        self.assertIn("Coverage ratio", text)

    def test_schema_doc_matches_code(self) -> None:
        self.assertEqual(json.loads(SCHEMA_DOC.read_text(encoding="utf-8")), L.LEDGER_SCHEMA)

    def test_non_object_root(self) -> None:
        self.assertFalse(L.validate_ledger({"schema_version": 3})["valid"])


class EvidenceLedgerCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "records"
        self.previous = cli.RECORDS_ROOT
        cli.RECORDS_ROOT = self.root
        store = RecordStore(ProgramPaths(self.root, "p1"))
        store.close()
        evidence = self.root / "p1" / "evidence" / "ac.json"
        evidence.write_text(
            json.dumps({"type": "access-control", "classification": "confirmed", "steps": []}), encoding="utf-8"
        )

    def tearDown(self) -> None:
        cli.RECORDS_ROOT = self.previous
        self.tmp.cleanup()

    def run_cli(self, *argv: str) -> str:
        args = cli.build_parser().parse_args(list(argv))
        buffer = StringIO()
        with redirect_stdout(buffer):
            args.func(args)
        return buffer.getvalue()

    def test_cli_round_trip_and_report_integration(self) -> None:
        self.run_cli("ledger", "init", "p1")
        self.run_cli(
            "ledger", "surface", "p1", "--id", "s1", "--kind", "endpoint", "--ref", "/x", "--status", "reviewed"
        )
        self.run_cli(
            "ledger",
            "surface",
            "p1",
            "--id",
            "s2",
            "--kind",
            "endpoint",
            "--ref",
            "/y",
            "--status",
            "blocked",
            "--blocker",
            "no second account",
        )
        out = self.run_cli("ledger", "import", "p1", "--evidence-path", "evidence/ac.json", "--surface", "s1")
        imported = json.loads(out.split("\n[i]")[0])
        self.assertFalse(imported["auto_confirmed"])
        cid = imported["candidate_id"]
        with self.assertRaises(L.LedgerError):
            self.run_cli(
                "ledger",
                "review",
                "p1",
                "--id",
                cid,
                "--state",
                "confirmed",
                "--reviewer",
                "bob",
                "--method",
                "human_manual",
                "--basis",
                "x",
                "--i-reviewed-the-evidence",
            )
        self.run_cli(
            "ledger",
            "review",
            "p1",
            "--id",
            cid,
            "--state",
            "rejected",
            "--reviewer",
            "bob",
            "--reason",
            "control_invalid",
            "--detail",
            "owner control failed",
        )
        result = json.loads(self.run_cli("ledger", "validate", "p1"))
        self.assertTrue(result["valid"])
        self.assertEqual(result["summary"]["candidate_states"]["rejected"], 1)
        report = self.run_cli("ledger", "report", "p1")
        self.assertIn("control_invalid", report)
        store = RecordStore(ProgramPaths(self.root, "p1"))
        try:
            program_report = build_program_report(store)
        finally:
            store.close()
        self.assertTrue(program_report["evidence_ledger"]["valid"])  # type: ignore[index]

    def test_validate_exits_nonzero_on_tampering(self) -> None:
        self.run_cli("ledger", "init", "p1")
        self.run_cli(
            "ledger", "surface", "p1", "--id", "s1", "--kind", "endpoint", "--ref", "/x", "--status", "reviewed"
        )
        self.run_cli("ledger", "evidence", "p1", "--id", "e1", "--path", "evidence/ac.json", "--tool", "access-check")
        (self.root / "p1" / "evidence" / "ac.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.run_cli("ledger", "validate", "p1")

    def test_schema_and_lab_commands(self) -> None:
        self.assertEqual(
            json.loads(self.run_cli("ledger", "schema"))["properties"]["schema_version"]["const"], L.SCHEMA_VERSION
        )
        metrics = json.loads(self.run_cli("lab", "evidence-ledger").split("\n[i]")[0])
        self.assertEqual(metrics["false_confirmations"], 0)


if __name__ == "__main__":
    unittest.main()
