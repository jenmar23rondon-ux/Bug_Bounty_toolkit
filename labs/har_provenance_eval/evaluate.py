"""Measure evidence-import HAR provenance metrics. Fully offline; works on old and new code."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import tempfile
import time
import tracemalloc
from typing import Any

from bugbounty_toolkit.analysis import evidence_engine
from labs.har_provenance_eval.fixtures import CANARY, fixtures, over_limit_entries


def _locators(bundle: dict[str, Any], path: Path) -> list[str]:
    resolved = str(path.resolve())
    return sorted(p["locator"] for r in bundle["records"] for p in r["provenance"] if p["source_path"] == resolved)


def evaluate(skip: frozenset[str] = frozenset()) -> dict[str, Any]:
    network: list[str] = []
    real_connect = socket.socket.connect

    def guard(self: socket.socket, address: Any) -> None:
        network.append(str(address))
        raise OSError("network disabled in evaluation")

    socket.socket.connect = guard  # type: ignore[method-assign]
    results: dict[str, Any] = {}
    totals = dict.fromkeys(
        (
            "fixtures",
            "imported",
            "valid_entries",
            "valid_preserved",
            "invalid_entries",
            "invalid_reported_exact",
            "invalid_emitted_as_records",
            "duplicates_expected",
            "duplicates_reported",
            "locator_consistent",
            "summary_present",
            "summary_valid",
            "secret_leaks",
        ),
        0,
    )
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for name, spec in fixtures().items():
                if name in skip:
                    results[name] = {"skipped": True}
                    continue
                path = Path(tmp) / f"{name}.har"
                path.write_bytes(spec["data"])
                declared = len(json.loads(spec["data"])["log"]["entries"])
                rejected: dict[int, str] = spec["rejected"]
                valid_idx = [i for i in range(declared) if i not in rejected]
                totals["fixtures"] += 1
                totals["valid_entries"] += len(valid_idx)
                totals["invalid_entries"] += len(rejected)
                totals["duplicates_expected"] += spec.get("duplicates", 0)
                row: dict[str, Any] = {"declared": declared}
                try:
                    bundle = evidence_engine.import_evidence([path], "har")
                except ValueError as exc:
                    row["error"] = str(exc)[:120]
                    results[name] = row
                    continue
                totals["imported"] += 1
                locs = _locators(bundle, path)
                preserved = sum(1 for i in valid_idx if f"/log/entries[{i}]" in locs)
                emitted_invalid = sum(1 for i in rejected if f"/log/entries[{i}]" in locs)
                totals["valid_preserved"] += preserved
                totals["invalid_emitted_as_records"] += emitted_invalid
                summary = bundle["inputs"][0].get("capture_import")
                if summary is not None:
                    totals["summary_present"] += 1
                    reported = {e["index"]: e["reason"] for e in summary.get("rejected_entries", [])}
                    totals["invalid_reported_exact"] += sum(1 for i, r in rejected.items() if reported.get(i) == r)
                    totals["duplicates_reported"] += int(summary.get("duplicate_entries", 0))
                    from bugbounty_toolkit.analysis.har_provenance import validate_capture_provenance

                    if validate_capture_provenance(bundle)["valid"]:
                        totals["summary_valid"] += 1
                if len(locs) == len(set(locs)) and all(
                    loc.startswith("/log/entries[") and int(loc[13:-1]) < declared for loc in locs
                ):
                    totals["locator_consistent"] += 1
                if CANARY in json.dumps(bundle):
                    totals["secret_leaks"] += 1
                row.update(records_emitted=len(locs), valid_preserved=preserved, invalid_emitted=emitted_invalid)
                results[name] = row
            # repeated import of the same file: bundle ids / summaries must be reproducible
            path = Path(tmp) / "valid.har"
            a = evidence_engine.import_evidence([path], "har")
            b = evidence_engine.import_evidence([path], "har")
            totals["repeat_inputs_identical"] = int(a["inputs"] == b["inputs"])
            both = evidence_engine.import_evidence([path, path], "har")
            totals["same_file_twice_records_parsed"] = both["summary"]["records_parsed"]
            totals["same_file_twice_records_unique"] = both["summary"]["records_unique"]
            # limits
            for count in (32, 33, 10_000, 10_001):
                big = Path(tmp) / f"n{count}.har"
                big.write_bytes(over_limit_entries(count))
                tracemalloc.start()
                started = time.perf_counter()
                try:
                    bundle = evidence_engine.import_evidence([big], "har")
                    outcome = f"ok:{bundle['summary']['records_parsed']}"
                except ValueError as exc:
                    outcome = "rejected:" + str(exc)[:60]
                elapsed = time.perf_counter() - started
                peak = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
                results[f"limit_{count}"] = {
                    "outcome": outcome,
                    "seconds": round(elapsed, 3),
                    "peak_mib": round(peak / 2**20, 1),
                }
    finally:
        socket.socket.connect = real_connect  # type: ignore[method-assign]
    totals["network_attempts"] = len(network)
    return {"totals": totals, "fixtures": results}


if __name__ == "__main__":
    json.dump(evaluate(frozenset(sys.argv[1:])), sys.stdout, indent=2, sort_keys=True)
    print()
