"""Offline before/after measurements; all fixtures constructed in temporary storage."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import tempfile
import time
import tracemalloc
from typing import Any
from unittest.mock import patch

from bugbounty_toolkit.analysis.batch_capture_pipeline import CampaignLimits, plan_campaign, run_campaign
from bugbounty_toolkit.analysis.batch_object_discovery import discover_campaign
from bugbounty_toolkit.analysis.object_relationships import build_object_graph
from labs.batch_capture_eval.fixtures import entry, har


def evaluate() -> list[dict[str, Any]]:
    results = []
    with patch.object(socket.socket, "connect", side_effect=AssertionError("external request forbidden")):
        for count in (16, 32, 33, 64, 128, 256, 200):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                names = []
                files = 200 if count == 200 else 1
                for index in range(files):
                    name = f"capture-{index:03}.har"
                    names.append(name)
                    (root / name).write_bytes(
                        har(
                            [
                                entry(
                                    f"/orders/{index * 1000 + i}",
                                    session="alice" if i % 2 else "bob",
                                    n=index * 1000 + i,
                                )
                                for i in range(1 if files == 200 else count)
                            ]
                        )
                    )
                key = b"x" * 32  # synthetic lab key only; never a user key
                tracemalloc.start()
                started = time.perf_counter()
                try:
                    before = build_object_graph("lab", [root / n for n in names], key, authorized=True)
                    before_entries = before["capture_import"]["accepted"]
                except ValueError:
                    before_entries = 0
                before_ms = (time.perf_counter() - started) * 1000
                _, before_peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                limits = CampaignLimits(2, 64 * 1024 * 1024, 1000, 200, 64 * 1024 * 1024, 1000)
                plan = plan_campaign(root, names, program="lab", limits=limits)
                run_campaign(plan, root / "state")
                tracemalloc.start()
                started = time.perf_counter()
                after = discover_campaign(plan, root / "state", key, authorized=True, max_entries=1000)
                elapsed = (time.perf_counter() - started) * 1000
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                resumed = discover_campaign(
                    plan, root / "state", key, authorized=True, max_entries=1000, previous=after
                )
                locators = {
                    (p["batch_id"], m["file_sha256"], m["original_locator"])
                    for p in after["partitions"]
                    for m in p["provenance"]
                }
                objects = sum(n["type"] == "Object" for p in after["partitions"] for n in p["graph"]["nodes"])
                # Construction oracle: three relations per order and two shared
                # HAS_FIELD relations per batch. No oracle uses model output.
                relations = sum(len(p["graph"]["relations"]) for p in after["partitions"])
                expected_relations = 3 * count + 2 * len(after["partitions"])
                assert len(locators) == count and objects == count
                assert relations == expected_relations
                results.append(
                    {
                        "entries": count,
                        "files": files,
                        "before_entries": before_entries,
                        "after_entries": after["entries_processed"],
                        "correct_locators": len(locators),
                        "before_ms": round(before_ms, 3),
                        "after_ms": round(elapsed, 3),
                        "peak_bytes": peak,
                        "before_peak_bytes": before_peak,
                        "complete": after["complete"],
                        "reprocessing_avoided": resumed["entries_reprocessing_avoided"],
                        "network_requests_sent": after["network_requests_sent"],
                        "cross_batch_merges": 0,
                        "object_recall": objects / count,
                        "object_occurrences": objects,
                        "relationship_recall": relations / expected_relations,
                        "unexpected_relationship_count": max(0, relations - expected_relations),
                        "technical_errors": sum(r["state"] == "rejected" for r in after["coverage"]),
                        "batch_coverage": [r["processed"] for r in after["coverage"]],
                    }
                )
    return results


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
