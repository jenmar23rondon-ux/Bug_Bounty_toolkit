"""Unit and integration tests for the evidence-gap next-step planner."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.analysis.evidence_gap_planner import (
    PLAN_SCHEMA_VERSION,
    build_plan,
    dumps_plan,
    step_id_for,
    validate_plan,
)
from bugbounty_toolkit.cli import build_parser
from bugbounty_toolkit.core.records import ProgramPaths
from labs.evidence_gap_planner_eval.corpus import NOW, build_split
from labs.evidence_gap_planner_eval.metrics import evaluate_split


class EvidenceGapPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.manifest = build_split("dev", self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _plan(self, program: str) -> dict:
        return build_plan(ProgramPaths(self.root, program), now=NOW)

    def test_schema_and_safety_flags(self) -> None:
        program = self.manifest["scenarios"][0]["program"]
        plan = self._plan(program)
        self.assertEqual(plan["schema_version"], PLAN_SCHEMA_VERSION)
        self.assertEqual(validate_plan(plan), [])
        self.assertFalse(plan["ai_used"])
        self.assertEqual(plan["network_requests_sent"], 0)
        self.assertEqual(plan["executions"], 0)
        self.assertEqual(plan["auto_confirmations"], 0)
        self.assertFalse(plan["ledger_modified"])
        for step in plan["plan"]:
            self.assertIs(step["execution_allowed"], False)
            self.assertIs(step["finding_confirmed"], False)
            self.assertIs(step["requires_human_review"], True)

    def test_deterministic_regeneration(self) -> None:
        program = self.manifest["scenarios"][1]["program"]
        a = dumps_plan(self._plan(program))
        b = dumps_plan(self._plan(program))
        self.assertEqual(a, b)
        self.assertEqual(step_id_for("x", "y", ["a", "b"]), step_id_for("x", "y", ["b", "a"]))

    def test_missing_owner_and_ready_controls(self) -> None:
        by_name = {s["scenario"]: s for s in self.manifest["scenarios"]}
        missing = by_name["02_missing_owner-dev"]
        plan = self._plan(missing["program"])
        self.assertEqual(plan["plan"][0]["step_type"], "identify_missing_owner_response")
        ready = by_name["01_ready_controls-dev"]
        plan2 = self._plan(ready["program"])
        self.assertEqual(plan2["plan"][0]["step_type"], "request_human_review")
        self.assertNotIn("identify_missing_owner_response", [s["step_type"] for s in plan2["plan"]])

    def test_tampered_evidence_blocks_confirmation_path(self) -> None:
        by_name = {s["scenario"]: s for s in self.manifest["scenarios"]}
        plan = self._plan(by_name["09_tampered_evidence-dev"]["program"])
        types = [s["step_type"] for s in plan["plan"]]
        self.assertEqual(types[0], "verify_evidence_digest")
        self.assertNotIn("request_human_review", types)

    def test_cookies_do_not_imply_distinct_accounts(self) -> None:
        by_name = {s["scenario"]: s for s in self.manifest["scenarios"]}
        plan = self._plan(by_name["03_cookies_not_accounts-dev"]["program"])
        self.assertEqual(plan["plan"][0]["step_type"], "attest_distinct_accounts")

    def test_blocked_and_abstain(self) -> None:
        by_name = {s["scenario"]: s for s in self.manifest["scenarios"]}
        blocked = self._plan(by_name["19_blocked_authorization-dev"]["program"])
        self.assertEqual(blocked["plan"][0]["step_type"], "blocked_missing_authorization")
        abstain = self._plan(by_name["20_insufficient_info-dev"]["program"])
        self.assertEqual(abstain["plan"][0]["step_type"], "abstain_insufficient_information")

    def test_reuse_control_across_candidates(self) -> None:
        by_name = {s["scenario"]: s for s in self.manifest["scenarios"]}
        plan = self._plan(by_name["17_reuse_negative_control-dev"]["program"])
        types = [s["step_type"] for s in plan["plan"]]
        self.assertIn("reuse_existing_control", types)
        self.assertNotIn("identify_missing_negative_control", types)

    def test_does_not_mutate_ledger(self) -> None:
        by_name = {s["scenario"]: s for s in self.manifest["scenarios"]}
        program = by_name["01_ready_controls-dev"]["program"]
        ledger_path = self.root / program / "ledger" / "evidence-ledger.json"
        before = ledger_path.read_bytes()
        self._plan(program)
        self.assertEqual(ledger_path.read_bytes(), before)

    def test_no_ledger_status(self) -> None:
        paths = ProgramPaths(self.root, "empty-program")
        paths.program_dir.mkdir(parents=True, exist_ok=True)
        plan = build_plan(paths)
        self.assertEqual(plan["status"], "no_ledger")
        self.assertEqual(plan["plan"], [])

    def test_cli_next_steps_dry_run(self) -> None:
        by_name = {s["scenario"]: s for s in self.manifest["scenarios"]}
        program = by_name["02_missing_owner-dev"]["program"]
        parser = build_parser()
        args = parser.parse_args(["investigation", "next-steps", program, "--dry-run", "--minimize"])
        with (
            patch("bugbounty_toolkit.cli.RECORDS_ROOT", self.root),
            patch("sys.stdout", new_callable=lambda: __import__("io").StringIO()) as out,
            patch("sys.stderr", new_callable=lambda: __import__("io").StringIO()),
        ):
            args.func(args)
            plan = json.loads(out.getvalue())
        self.assertEqual(plan["schema_version"], PLAN_SCHEMA_VERSION)
        self.assertEqual(validate_plan(plan), [])

    def test_cli_schema(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["investigation", "next-steps", "any", "--schema"])
        with patch("sys.stdout", new_callable=lambda: __import__("io").StringIO()) as out:
            args.func(args)
            schema = json.loads(out.getvalue())
        self.assertIn("properties", schema)

    def test_lab_metrics_final_improves_utility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            metrics = evaluate_split("final", Path(tmp) / "final")
        self.assertEqual(metrics["security"]["network_requests_sent"], 0)
        self.assertEqual(metrics["security"]["executions"], 0)
        self.assertEqual(metrics["security"]["auto_confirmations"], 0)
        self.assertGreaterEqual(metrics["quality"]["precision_at_1"], 0.8)
        self.assertGreater(metrics["utility"]["redundant_step_reduction_pct_vs_manual"], 0)
        self.assertEqual(metrics["utility"]["deterministic_regeneration_rate"], 1.0)
        self.assertTrue(metrics["synthetic"])


if __name__ == "__main__":
    unittest.main()
