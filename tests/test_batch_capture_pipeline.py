from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import tempfile
from typing import Any
import unittest

from bugbounty_toolkit.analysis import batch_capture_pipeline as bcp
from bugbounty_toolkit.analysis import evidence_engine
from labs.batch_capture_eval.fixtures import CANARY, entry, har

LIMITS = bcp.CampaignLimits(2, 16 * 1024 * 1024, 5_000, 100, 64 * 1024 * 1024, 50_000)


class BatchCapturePipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        os.chmod(self.tmp, 0o700)
        self.root = self.tmp / "in"
        self.root.mkdir(mode=0o700)
        self.state = self.tmp / "state"
        self.real_connect = socket.socket.connect

        def guard(sock: socket.socket, address: Any) -> None:
            raise AssertionError("network access attempted")

        socket.socket.connect = guard  # type: ignore[method-assign]

    def tearDown(self) -> None:
        socket.socket.connect = self.real_connect  # type: ignore[method-assign]
        self._tmp.cleanup()

    def write(self, name: str, data: bytes) -> None:
        (self.root / name).write_bytes(data)

    def files(self, count: int, per: int = 3) -> list[str]:
        names = []
        for f in range(count):
            name = f"p{f}.har"
            self.write(name, har([entry(f"/x/{f}/{i}", session=f"s{f % 2}", n=i) for i in range(per)]))
            names.append(name)
        return names

    def plan(self, names: list[str], limits: bcp.CampaignLimits = LIMITS, **kw: Any) -> bcp.CampaignPlan:
        return bcp.plan_campaign(self.root, names, program="lab", limits=limits, **kw)

    def test_plan_is_deterministic_and_order_independent(self) -> None:
        names = self.files(5)
        a, b = self.plan(names), self.plan(list(reversed(names)))
        self.assertEqual(a.manifest(), b.manifest())
        self.assertEqual(len(a.batches), 3)
        self.assertEqual(len(a.campaign_id), 24)

    def test_complete_campaign_preserves_every_locator(self) -> None:
        names = self.files(5)
        summary = bcp.run_campaign(self.plan(names), self.state)
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["records_parsed"], 15)
        self.assertEqual(summary["cross_batch_graph_merge"], "not_performed")
        self.assertEqual(summary["network_requests_sent"], 0)
        self.assertEqual(summary["vulnerabilities_confirmed"], 0)
        locators = set()
        for path in (self.state / "batches").glob("*.json"):
            for record in json.loads(path.read_text())["records"]:
                for prov in record["provenance"]:
                    locators.add((Path(prov["source_path"]).name, prov["locator"]))
        self.assertEqual(len(locators), 15)

    def test_equivalent_to_monolithic_import(self) -> None:
        names = self.files(4)
        mono = evidence_engine.import_evidence([self.root / n for n in names], "auto", "partial")
        bcp.run_campaign(self.plan(names), self.state)
        batched = [r for p in (self.state / "batches").glob("*.json") for r in json.loads(p.read_text())["records"]]

        def view(rows: list[dict[str, Any]]) -> list[str]:
            return sorted(
                json.dumps([r["host"], r["endpoint"], r["method"], r["status_code"], r["provenance"]], sort_keys=True)
                for r in rows
            )

        self.assertEqual(view(mono["records"]), view(batched))  # type: ignore[arg-type]

    def test_private_state_and_no_canary_leak(self) -> None:
        summary = bcp.run_campaign(self.plan(self.files(2)), self.state)
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o700)
        for path in self.state.rglob("*.json"):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertNotIn(CANARY, path.read_text())
        self.assertNotIn(CANARY, json.dumps(summary))

    def test_interrupt_and_resume_without_reprocessing(self) -> None:
        plan = self.plan(self.files(6))
        first = bcp.run_campaign(plan, self.state, max_batches=1)
        self.assertEqual(first["status"], "incomplete")
        self.assertFalse(first["complete"])
        self.assertEqual(first["batches_by_state"]["pending"], 2)
        second = bcp.run_campaign(plan, self.state)
        self.assertEqual((second["resume"]["reused"], second["resume"]["executed"]), (1, 2))
        self.assertEqual(second["status"], "complete")
        third = bcp.run_campaign(plan, self.state)
        self.assertEqual(third["resume"]["executed"], 0)

    def test_crash_mid_batch_keeps_finished_batches(self) -> None:
        plan = self.plan(self.files(6))
        calls = {"n": 0}

        def flaky(paths: list[Path], fmt: str, mode: str) -> dict[str, Any]:
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt
            return evidence_engine.import_evidence(paths, fmt, mode)

        with self.assertRaises(KeyboardInterrupt):
            bcp.run_campaign(plan, self.state, importer=flaky)
        resumed = bcp.run_campaign(plan, self.state)
        self.assertEqual(resumed["resume"]["reused"], 1)
        self.assertEqual(resumed["status"], "complete")

    def test_altered_output_is_reprocessed(self) -> None:
        plan = self.plan(self.files(4))
        bcp.run_campaign(plan, self.state)
        victim = sorted((self.state / "batches").glob("*.json"))[0]
        victim.write_bytes(victim.read_bytes() + b" ")
        again = bcp.run_campaign(plan, self.state)
        self.assertEqual(again["resume"]["reprocessed_output_altered"], 1)
        self.assertEqual(again["resume"]["executed"], 1)

    def test_changed_source_refused_then_only_its_batch_rerun(self) -> None:
        names = self.files(6)
        bcp.run_campaign(self.plan(names), self.state)
        self.write("p5.har", har([entry("/changed", session="s0")]))
        with self.assertRaises(bcp.CampaignError) as ctx:
            bcp.run_campaign(self.plan(names), self.state)
        self.assertEqual(ctx.exception.reason, "source_changed")
        changed = bcp.run_campaign(self.plan(names), self.state, allow_source_changes=True)
        self.assertEqual((changed["resume"]["reused"], changed["resume"]["executed"]), (2, 1))

    def test_change_during_batch_fails_batch(self) -> None:
        names = self.files(2)
        plan = self.plan(names)

        def mutate(paths: list[Path], fmt: str, mode: str) -> dict[str, Any]:
            bundle = evidence_engine.import_evidence(paths, fmt, mode)
            self.write("p0.har", har([entry("/swap", session="s0")]))
            return bundle

        summary = bcp.run_campaign(plan, self.state, importer=mutate)
        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["batches_by_state"]["failed"], 1)

    def test_mismatched_context_refused(self) -> None:
        names = self.files(2)
        bcp.run_campaign(self.plan(names), self.state)
        other = bcp.plan_campaign(self.root, names, program="other", limits=LIMITS)
        with self.assertRaises(bcp.CampaignError) as ctx:
            bcp.run_campaign(other, self.state)
        self.assertEqual(ctx.exception.reason, "campaign_mismatch")
        with self.assertRaises(bcp.CampaignError):
            bcp.run_campaign(self.plan(names, har_mode="strict"), self.state)

    def test_campaign_total_cannot_be_evaded_by_batching(self) -> None:
        tight = bcp.CampaignLimits(1, 16 * 1024 * 1024, 5, 100, 64 * 1024 * 1024, 7)
        summary = bcp.run_campaign(self.plan(self.files(4), tight), self.state)
        self.assertEqual(summary["status"], "partial_limit_reached")
        self.assertEqual(summary["records_parsed"], 6)  # 3 + 3; a third batch would make 9 > 7
        self.assertEqual(summary["batches_by_state"]["blocked_by_campaign_limit"], 2)
        self.assertFalse(summary["complete"])

    def test_per_batch_record_limit_fails_without_truncation(self) -> None:
        small = bcp.CampaignLimits(2, 16 * 1024 * 1024, 4, 100, 64 * 1024 * 1024, 100)
        summary = bcp.run_campaign(self.plan(self.files(2), small), self.state)
        self.assertEqual(summary["batches_by_state"]["failed"], 1)
        self.assertEqual(summary["records_parsed"], 0)
        self.assertFalse(list((self.state / "batches").glob("*.json")))

    def test_limits_must_be_explicit_and_within_stage_limits(self) -> None:
        bad = [
            bcp.CampaignLimits(evidence_engine.MAX_INPUT_FILES + 1, 1, 1, 1000, 1, 1),
            bcp.CampaignLimits(1, 1, evidence_engine.MAX_RECORDS + 1, 1, 1, 100_000),
            bcp.CampaignLimits(1, 1, 1, 1, 1, bcp.HARD_MAX_TOTAL_RECORDS + 1),
            bcp.CampaignLimits(1, 1, 10, 1, 1, 5),
            bcp.CampaignLimits(0, 1, 1, 1, 1, 1),
        ]
        names = self.files(1)
        for limits in bad:
            with self.assertRaises(bcp.CampaignError):
                self.plan(names, limits)

    def test_total_file_and_byte_limits(self) -> None:
        names = self.files(3)
        with self.assertRaises(bcp.CampaignError):
            self.plan(names, bcp.CampaignLimits(1, 16 * 1024 * 1024, 10, 2, 1024 * 1024, 100))
        size = (self.root / names[0]).stat().st_size
        plan = self.plan(names, bcp.CampaignLimits(2, 16 * 1024 * 1024, 10, 10, size, 100))
        self.assertEqual([f.state for f in plan.files].count("omitted_campaign_limit"), 2)
        summary = bcp.run_campaign(plan, self.state)
        self.assertEqual(summary["status"], "partial_limit_reached")

    def test_duplicate_corrupt_and_oversize_files_are_classified(self) -> None:
        names = self.files(1)
        self.write("copy.har", (self.root / names[0]).read_bytes())
        self.write("broken.har", b'{"log":{"entries":[')
        with (self.root / "huge.har").open("wb") as handle:
            handle.truncate(evidence_engine.MAX_INPUT_BYTES + 1)
        plan = self.plan([*names, "copy.har", "broken.har", "huge.har"])
        states = {f.relpath: f.state for f in plan.files}
        self.assertEqual(states["p0.har"], "duplicate_file")  # first in sorted order is canonical
        self.assertEqual(plan.files[[f.relpath for f in plan.files].index("p0.har")].duplicate_of, "copy.har")
        self.assertEqual(states["huge.har"], "omitted_file_limit")
        summary = bcp.run_campaign(plan, self.state)
        self.assertEqual(summary["files_by_state"]["rejected_file"], 1)
        self.assertEqual(summary["file_errors"][0]["error"], "har:json_invalid")
        self.assertNotIn("broken", json.dumps(summary))
        self.assertEqual(summary["status"], "partial_limit_reached")
        self.assertIn("some_input_files_rejected", summary["warnings"])

    def test_entry_rejections_and_cross_file_duplicates_reported(self) -> None:
        good = entry("/a", session="s0")
        self.write("a.har", har([good, {"request": good["request"]}]))
        self.write("b.har", har([good, entry("/b", session="s0")]))
        summary = bcp.run_campaign(
            self.plan(["a.har", "b.har"], bcp.CampaignLimits(1, 16 * 1024 * 1024, 10, 10, 1 << 20, 100)), self.state
        )
        self.assertEqual(summary["har_rejections_by_reason"], {"response_missing": 1})
        self.assertEqual(summary["cross_batch_duplicate_har_entries"], 1)
        self.assertEqual(summary["cross_file_duplicate_har_entries"], 1)

    def test_paths_symlinks_and_state_dir_refused(self) -> None:
        names = self.files(1)
        (self.root / "link.har").symlink_to(self.root / names[0])
        for rel in ("link.har", "../x.har", "/etc/passwd", "", "missing.har"):
            with self.assertRaises(ValueError):
                self.plan([rel])
        with self.assertRaises(bcp.CampaignError):
            self.plan(names + names)
        with self.assertRaises(bcp.CampaignError):
            bcp.plan_campaign(self.root, names, program="Bad Program", limits=LIMITS)
        open_dir = self.tmp / "open"
        open_dir.mkdir(mode=0o755)
        os.chmod(open_dir, 0o755)
        with self.assertRaises(bcp.CampaignError):
            bcp.run_campaign(self.plan(names), open_dir)

    def test_corrupt_state_refused(self) -> None:
        plan = self.plan(self.files(1))
        bcp.run_campaign(plan, self.state)
        state = self.state / "campaign-state.json"
        state.write_text("{not json")
        with self.assertRaises(bcp.CampaignError):
            bcp.run_campaign(plan, self.state)
        state.write_text(json.dumps({"schema": "other"}))
        with self.assertRaises(bcp.CampaignError):
            bcp.run_campaign(plan, self.state)

    def test_frozen_lab_corpus_and_metrics(self) -> None:
        from labs.batch_capture_eval import evaluate

        evaluate.verify_frozen()
        report = evaluate.evaluate("dev")
        totals = report["totals"]
        self.assertEqual(totals["lost_records"], 0)
        self.assertEqual(totals["mixed_sessions"], 0)
        self.assertEqual(totals["leaks"], 0)
        self.assertEqual(totals["partial_marked_complete"], 0)
        self.assertEqual(totals["expectations_failed"], 0)
        self.assertEqual(totals["rejects_expected"], totals["rejects_reported"])
        self.assertEqual(report["network_attempts"], 0)
        self.assertTrue(report["resilience"]["changed_file_refused"])


if __name__ == "__main__":
    unittest.main()
