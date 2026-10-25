from __future__ import annotations

from contextlib import redirect_stdout
import json
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.investigation_memory import InvestigationMemory
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore


class InvestigationMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.records = RecordStore(ProgramPaths(self.root / "records", "lab"))
        self.memory = InvestigationMemory(self.records)

    def tearDown(self) -> None:
        self.records.close()
        self.temporary.cleanup()

    def test_saved_investigation_can_close_and_resume_with_same_bundle(self) -> None:
        saved = self.memory.save_snapshot(
            "web-review-1",
            "a" * 24,
            "evidence/ai-investigations/investigation-1.json",
            {"correlate": {"status": "complete"}},
        )
        self.assertEqual(saved["status"], "active")
        closed = self.memory.close("web-review-1")
        self.assertEqual(closed["status"], "closed")
        resumed = self.memory.save_snapshot(
            "web-review-1",
            "a" * 24,
            "evidence/ai-investigations/investigation-2.json",
            {"correlate": {"status": "complete"}, "route": {"status": "plan_ready"}},
            resume=True,
        )
        self.assertEqual(resumed["status"], "active")
        self.assertEqual(resumed["resume_count"], 1)
        self.assertEqual([event["event_type"] for event in resumed["events"]], ["saved", "closed", "resumed"])
        self.assertEqual(resumed["snapshot_ref"], "evidence/ai-investigations/investigation-2.json")

    def test_resume_requires_closed_record_and_same_bundle(self) -> None:
        self.memory.save_snapshot("review", "b" * 24, "evidence/review.json", {})
        with self.assertRaisesRegex(ValueError, "Only a closed"):
            self.memory.save_snapshot("review", "b" * 24, "evidence/review-2.json", {}, resume=True)
        self.memory.close("review")
        with self.assertRaisesRegex(ValueError, "same evidence bundle"):
            self.memory.save_snapshot("review", "c" * 24, "evidence/review-2.json", {}, resume=True)

    def test_close_unknown_or_already_closed_and_invalid_paths_fail_clearly(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not exist"):
            self.memory.close("missing")
        for snapshot in ("../secret.json", "C:/secret.json", "evidence\\secret.json"):
            with self.subTest(snapshot=snapshot), self.assertRaisesRegex(ValueError, "snapshot reference"):
                self.memory.save_snapshot("safe-id", "d" * 24, snapshot, {})
        self.memory.save_snapshot("safe-id", "d" * 24, "evidence/review.json", {})
        self.memory.close("safe-id")
        with self.assertRaisesRegex(ValueError, "already closed"):
            self.memory.close("safe-id")

    def test_ai_investigate_cli_persists_closes_and_resumes_session(self) -> None:
        original_root = cli.RECORDS_ROOT
        cli.RECORDS_ROOT = self.root / "cli-records"
        bundle = self.root / "bundle.json"
        bundle.write_text(
            json.dumps(
                {
                    "type": "unified-evidence-bundle",
                    "bundle_id": "e" * 24,
                    "records": [
                        {
                            "evidence_id": f"{index:024x}",
                            "source_tools": ["burp"],
                            "host": "lab.example",
                            "endpoint": "/api/orders/{id}",
                            "method": "GET",
                            "parameters": ["order_id"],
                            "status_code": 200,
                            "session_fingerprint": f"session-{index}",
                            "resource_fingerprint": f"resource-{index}",
                            "response_fingerprint": f"response-{index}",
                            "response_shape_fingerprint": f"shape-{index}",
                            "sensitivity": "sensitive",
                            "validation_status": "parsed",
                            "provenance": [{"source_path": "fixture.xml", "locator": f"item:{index}"}],
                        }
                        for index in (1, 2)
                    ],
                }
            ),
            encoding="utf-8",
        )
        try:
            for resume in (False, True):
                argv = ["ai", "investigate", "lab", "--input", str(bundle), "--session-id", "e2e-review"]
                if resume:
                    argv.append("--resume-session")
                args = cli.build_parser().parse_args(argv)
                with redirect_stdout(StringIO()):
                    args.func(args)
                if not resume:
                    close_args = cli.build_parser().parse_args(["investigation", "close", "lab", "--id", "e2e-review"])
                    with redirect_stdout(StringIO()):
                        close_args.func(close_args)
            status_args = cli.build_parser().parse_args(["investigation", "status", "lab", "--id", "e2e-review"])
            output = StringIO()
            with redirect_stdout(output):
                status_args.func(status_args)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "active")
            self.assertEqual(result["resume_count"], 1)
            self.assertEqual([event["event_type"] for event in result["events"]], ["saved", "closed", "resumed"])
            snapshots = list((self.root / "cli-records" / "lab" / "evidence" / "ai-investigations").glob("*.json"))
            self.assertEqual(len(snapshots), 2)
        finally:
            cli.RECORDS_ROOT = original_root


if __name__ == "__main__":
    unittest.main()
