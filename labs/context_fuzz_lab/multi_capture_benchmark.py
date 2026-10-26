"""Offline before/after measurement for fuzz-plan multi-format capture import.

"before" = the historical HAR-only entry point (``load_har_for_planning``), which is unchanged
by this PR. "after" = the common capture adapter. Same synthetic fixtures for both.
Run: python labs/context_fuzz_lab/multi_capture_benchmark.py [--json]
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from bugbounty_toolkit.core.scope_validator import ScopeValidator  # noqa: E402
from bugbounty_toolkit.fuzzing.context_planner import build_fuzz_plan  # noqa: E402
from bugbounty_toolkit.fuzzing.wordlist_manager import register_collection  # noqa: E402

LAB = Path(__file__).resolve().parent
FIX = LAB / "fixtures"
ORIGIN = "http://127.0.0.1:8191"
SECRET = "SYNTH-SECRET"
GROUND = json.loads((LAB / "ground_truth.json").read_text(encoding="utf-8"))


def _cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = [
        {"name": "har", "path": FIX / "capture.har", "format": "har"},
        {"name": "burp-xml", "path": FIX / "capture.burp.xml", "format": "burp-xml"},
    ]
    for index in range(9):
        cases.append(
            {
                "name": f"raw-http-{index:02d}",
                "path": FIX / "raw" / f"{index:02d}.request.http",
                "format": "raw-http",
                "response": FIX / "raw" / f"{index:02d}.response.http",
                "origin": ORIGIN,
            }
        )
    return cases


def _run(case: dict[str, Any], mode: str, collection: Any, scope: ScopeValidator) -> dict[str, Any]:
    calls = {"network": 0}

    def blocked(*_a: Any, **_k: Any) -> Any:
        calls["network"] += 1
        raise OSError("network blocked in benchmark")

    tracemalloc.start()
    started = time.perf_counter()
    try:
        with (
            patch.object(socket.socket, "connect", blocked),
            patch("socket.create_connection", blocked),
            patch("socket.getaddrinfo", blocked),
        ):
            kwargs: dict[str, Any] = {}
            if mode == "after":
                kwargs = {
                    "capture_format": case["format"],
                    "response_path": case.get("response"),
                    "origin": case.get("origin"),
                }
            plan = build_fuzz_plan("bench", case["path"], collections=[collection], scope=scope, max_tests=20, **kwargs)
        error = None
    except ValueError as exc:
        plan, error = None, getattr(exc, "reason", type(exc).__name__)
    elapsed = (time.perf_counter() - started) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if plan is None:
        return {"accepted": 0, "error": error, "network": calls["network"], "ms": round(elapsed, 2)}
    doc = plan.to_dict()
    blob = json.dumps(doc)
    assert plan.context is not None
    known = set(GROUND["known_routes"]) | set(GROUND["protected_routes"])
    observed = set(plan.context.observed_paths)
    false_targets = [
        t
        for t in plan.targets
        if not t.host.startswith("127.0.0.1")
        or not any(
            t.url_template.split("://", 1)[-1].split("/", 1)[-1].startswith(p.lstrip("/").rsplit("/", 1)[0])
            for p in known
        )
    ]
    imp = plan.context.capture_import
    return {
        "accepted": imp["accepted"],
        "rejected": imp["rejected"],
        "duplicates": imp["duplicate_entries"],
        "paths": sorted(observed),
        "parameters": list(plan.context.parameters),
        "targets": sorted(t.url_template for t in plan.targets),
        "false_targets": len(false_targets),
        "secrets_in_plan": blob.count(SECRET),
        "provenance_locators": len(imp.get("provenance", {}).get("locators", []))
        if imp["format"] != "har"
        else imp["accepted"],
        "network": calls["network"],
        "ms": round(elapsed, 2),
        "peak_kib": round(peak / 1024, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        collection = register_collection(root / "wl.json", "lab", LAB / "wordlists")
        (root / "scope.txt").write_text(ORIGIN + "\n", encoding="utf-8")
        scope = ScopeValidator(root / "scope.txt")
        rows = {
            mode: {case["name"]: _run(case, mode, collection, scope) for case in _cases()}
            for mode in ("before", "after")
        }
    summary: dict[str, Any] = {}
    for mode, results in rows.items():
        raw = [v for k, v in results.items() if k.startswith("raw-http")]
        raw_paths = sorted({p for r in raw for p in r.get("paths", [])})
        raw_params = sorted({p for r in raw for p in r.get("parameters", [])})
        summary[mode] = {
            "formats_accepted": sorted(
                {k.split("-0")[0] if k.startswith("raw") else k for k, v in results.items() if v["accepted"]}
            ),
            "captures_accepted": sum(v["accepted"] for v in results.values()),
            "har": {k: results["har"].get(k) for k in ("accepted", "paths", "parameters", "targets")},
            "burp_xml_parity_with_har": results["burp-xml"].get("targets") == results["har"].get("targets")
            and results["burp-xml"].get("paths") == results["har"].get("paths")
            and results["burp-xml"].get("parameters") == results["har"].get("parameters"),
            "burp_xml_error": results["burp-xml"].get("error"),
            "raw_paths_parity_with_har": raw_paths == results["har"].get("paths"),
            "raw_params_parity_with_har": raw_params == results["har"].get("parameters"),
            "raw_error": raw[0].get("error"),
            "false_targets": sum(v.get("false_targets", 0) for v in results.values()),
            "secrets_in_plans": sum(v.get("secrets_in_plan", 0) for v in results.values()),
            "provenance_locators": sum(v.get("provenance_locators", 0) for v in results.values()),
            "network_calls": sum(v["network"] for v in results.values()),
            "ms_total": round(sum(v["ms"] for v in results.values()), 1),
            "peak_kib_max": max(v.get("peak_kib", 0) for v in results.values()),
        }
    print(json.dumps(summary if not args.json else {"summary": summary, "rows": rows}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
