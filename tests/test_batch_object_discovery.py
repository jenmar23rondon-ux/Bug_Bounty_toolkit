from __future__ import annotations

import json
from pathlib import Path
import socket
import shutil
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

from bugbounty_toolkit.analysis.batch_capture_pipeline import CampaignLimits, plan_campaign, run_campaign
from bugbounty_toolkit.analysis.batch_object_discovery import discover_campaign
from labs.batch_capture_eval.fixtures import CANARY, entry, har


class BatchObjectDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = b"s" * 32
        guard = patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden"))
        guard.start()
        self.addCleanup(guard.stop)

    def prepare(self, counts: tuple[int, ...], *, interrupt: bool = False) -> Any:
        shutil.rmtree(self.root / "state", ignore_errors=True)
        names = []
        for f, count in enumerate(counts):
            name = f"{f}.har"
            names.append(name)
            (self.root / name).write_bytes(
                har([entry(f"/orders/{i}", session="alice" if i % 2 else "bob", n=f * 1000 + i) for i in range(count)])
            )
        limits = CampaignLimits(1, 32 * 1024 * 1024, 1000, 200, 64 * 1024 * 1024, 1000)
        plan = plan_campaign(self.root, names, program="lab", limits=limits)
        run_campaign(plan, self.root / "state", max_batches=1 if interrupt else None)
        return plan

    def discover(self, plan: Any, **kw: Any) -> dict[str, Any]:
        return discover_campaign(plan, self.root / "state", self.key, authorized=True, max_entries=1000, **kw)

    def test_sizes_and_locators(self) -> None:
        for size in (16, 32, 33, 64, 128, 256):
            with self.subTest(size=size):
                plan = self.prepare((size,))
                result = self.discover(plan)
                self.assertTrue(result["complete"], result["coverage"])
                self.assertEqual(result["entries_processed"], size)
                self.assertEqual(
                    {p["original_locator"] for p in result["partitions"][0]["provenance"]},
                    {f"/log/entries[{i}]" for i in range(size)},
                )
                self.assertNotIn(CANARY, json.dumps(result))

    def test_interrupted_resume_and_authenticated_reuse(self) -> None:
        plan = self.prepare((33, 32), interrupt=True)
        first = self.discover(plan)
        self.assertFalse(first["complete"])
        run_campaign(plan, self.root / "state")
        second = self.discover(plan, previous=first)
        self.assertTrue(second["complete"])
        self.assertEqual(second["entries_reprocessing_avoided"], 33)
        self.assertEqual(len(second["partitions"]), 2)
        self.assertFalse(second["global_ranking_guaranteed"])
        first["partitions"][0]["entries_processed"] = 900
        third = self.discover(plan, previous=first)
        self.assertEqual(third["entries_reprocessing_avoided"], 0)
        self.assertEqual(third["entries_processed"], 65)

    def test_modified_bundle_and_source_refused(self) -> None:
        plan = self.prepare((33,))
        path = next((self.root / "state" / "batches").glob("*.json"))
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        self.assertEqual(self.discover(plan)["partitions"], [])
        path.write_bytes(original)
        (self.root / "0.har").write_bytes(b"{}")
        self.assertFalse(self.discover(plan)["complete"])

    def test_global_and_graph_limits_are_explicit(self) -> None:
        plan = self.prepare((33, 32))
        result = discover_campaign(plan, self.root / "state", self.key, authorized=True, max_entries=33)
        self.assertEqual(result["entries_processed"], 33)
        self.assertEqual(result["coverage"][1]["reason"], "global_limit_reached")
        self.assertFalse(result["complete"])
        plan = self.prepare((257,))
        result = self.discover(plan)
        self.assertFalse(result["complete"])
        self.assertEqual(result["partitions"], [])

    def test_authorization_and_identity(self) -> None:
        plan = self.prepare((2,))
        with self.assertRaises(ValueError):
            discover_campaign(plan, self.root / "state", self.key, authorized=False, max_entries=1000)
        plan.program = "other"
        with self.assertRaises(ValueError):
            self.discover(plan)

    def test_namespaces_origins_sessions_and_duplicate_batches(self) -> None:
        names = []
        for index in range(2):
            name = f"{index}.har"
            names.append(name)
            # Same literal in two namespaces and origins; two captured sessions.
            rows = [
                entry("/orders/42", session="alice", n=42),
                entry("/users/42", session="bob", n=42),
                entry("/orders/42", session="alice", host="other.test", n=42),
            ]
            rows.append(entry("/orders/42", session="alice", n=42))
            rows[0]["startedDateTime"] = f"2026-01-0{index + 1}T00:00:00Z"
            (self.root / name).write_bytes(har(rows))
        limits = CampaignLimits(1, 32 * 1024 * 1024, 1000, 200, 64 * 1024 * 1024, 1000)
        plan = plan_campaign(self.root, names, program="lab", limits=limits)
        run_campaign(plan, self.root / "state")
        result = self.discover(plan)
        self.assertEqual(result["entries_processed"], 8)
        self.assertEqual(len(result["partitions"]), 2)
        for partition in result["partitions"]:
            graph = partition["graph"]
            self.assertEqual(sum(n["type"] == "SessionContext" for n in graph["nodes"]), 3)
            objects = [n for n in graph["nodes"] if n["type"] == "Object"]
            self.assertGreaterEqual(len(objects), 3)
            self.assertEqual(len(partition["provenance"]), 4)
        self.assertEqual(result["cross_batch_graph_merge"], "not_performed")
        self.assertIsNotNone(result["ambiguous_joins"])

    def test_partial_graph_rejected_entry_and_pending_orphan(self) -> None:
        plan = self.prepare((2, 2), interrupt=True)
        # An old/orphan bundle must never be consumed for a pending batch.
        paths = self.root / "state" / "batches"
        orphan = paths / f"{plan.batches[1].batch_id}.json"
        orphan.write_bytes(next(paths.glob("*.json")).read_bytes())
        result = self.discover(plan)
        self.assertEqual(len(result["partitions"]), 1)
        self.assertFalse(result["complete"])
        shutil.rmtree(self.root / "state")
        row = entry("/orders/42", session="alice", n=42)
        row["response"]["content"]["text"] = json.dumps({"order_id": list(range(100))})
        (self.root / "0.har").write_bytes(har([row, entry("/orders/43", session="bob", n=43)]))
        plan = plan_campaign(self.root, ["0.har"], program="lab", limits=plan.limits)
        run_campaign(plan, self.root / "state")
        result = self.discover(plan)
        self.assertFalse(result["complete"])
        self.assertGreater(result["entries_rejected_at_discovery"], 0)

    def test_symlink_and_wrong_key_do_not_reuse(self) -> None:
        plan = self.prepare((3,))
        first = self.discover(plan)
        self.key = b"t" * 32
        result = self.discover(plan, previous=first)
        self.assertEqual(result["entries_reprocessing_avoided"], 0)
        path = next((self.root / "state" / "batches").glob("*.json"))
        moved = self.root / "moved.json"
        path.rename(moved)
        path.symlink_to(moved)
        self.assertEqual(self.discover(plan)["partitions"], [])

    def test_global_graph_budget_stops_consolidation(self) -> None:
        plan = self.prepare((2, 3))
        with patch("bugbounty_toolkit.analysis.batch_object_discovery.MAX_GRAPH_NODES", 1):
            result = self.discover(plan)
        self.assertFalse(result["complete"])
        self.assertEqual(result["partitions"], [])
        self.assertTrue(all(r["reason"] == "global_graph_limit_reached" for r in result["coverage"]))

    def test_rejected_har_entries_remain_partial_and_legacy_is_refused(self) -> None:
        plan = self.prepare((2,))
        shutil.rmtree(self.root / "state")
        (self.root / "0.har").write_bytes(har([entry("/orders/42", session="a", n=42), None]))
        plan = plan_campaign(self.root, ["0.har"], program="lab", limits=plan.limits)
        run_campaign(plan, self.root / "state")
        result = self.discover(plan)
        self.assertFalse(result["complete"])
        self.assertEqual(result["entries_rejected_at_import"], 1)
        self.assertEqual(result["entries_processed"], 1)
        plan.har_mode = "compat"
        with self.assertRaises(ValueError):
            self.discover(plan)


if __name__ == "__main__":
    unittest.main()
